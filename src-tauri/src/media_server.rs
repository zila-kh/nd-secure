use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::GALLERY_DOMAIN,
    error::{Result, VaultError},
    gallery::{ContainerReader, GalleryRepository},
    session::SessionState,
};

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_BYTES: usize = TOKEN_BYTES * 2;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_TARGET_BYTES: usize = 1024;
const MAX_RANGE_HEADER_BYTES: usize = 256;
const MAX_ORIGIN_BYTES: usize = 2048;
const STREAM_WINDOW_BYTES: u64 = 1024 * 1024;
const GRANT_TTL_SECONDS: u64 = 20 * 60;
const READ_TIMEOUT_SECONDS: u64 = 10;
const WRITE_TIMEOUT_SECONDS: u64 = 30;

#[cfg(target_os = "android")]
const MAX_CONNECTIONS: usize = 4;
#[cfg(not(target_os = "android"))]
const MAX_CONNECTIONS: usize = 8;

#[derive(Debug, Clone, Copy)]
struct StreamGrant {
    media_id: Uuid,
    expires_at: Instant,
}

pub struct MediaServer {
    port: u16,
    grants: Arc<Mutex<HashMap<[u8; 32], StreamGrant>>>,
}

impl MediaServer {
    pub fn start(session: Arc<SessionState>, gallery: Arc<GalleryRepository>) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let grants = Arc::new(Mutex::new(HashMap::new()));
        let accept_grants = Arc::clone(&grants);
        thread::Builder::new()
            .name("nd-vault-media-accept".into())
            .spawn(move || accept_loop(listener, port, session, gallery, accept_grants))
            .map_err(|error| {
                VaultError::Platform(format!("unable to start the encrypted media server: {error}"))
            })?;

        Ok(Self { port, grants })
    }

    pub fn issue(&self, media_id: Uuid) -> Result<(String, String)> {
        let mut random = [0_u8; TOKEN_BYTES];
        let mut rng = OsRng;

        for _ in 0..8 {
            rng.fill_bytes(&mut random);
            let digest = token_digest(&random);
            let mut grants = self.grants.lock();
            let now = Instant::now();
            grants.retain(|_, grant| grant.expires_at > now);
            if grants.contains_key(&digest) {
                continue;
            }
            grants.insert(
                digest,
                StreamGrant { media_id, expires_at: now + Duration::from_secs(GRANT_TTL_SECONDS) },
            );
            drop(grants);

            let token = encode_token(&random);
            random.zeroize();
            let url = format!("http://127.0.0.1:{}/v1/{token}/media/{media_id}", self.port);
            return Ok((url, token));
        }

        random.zeroize();
        Err(VaultError::Platform("unable to allocate an encrypted media stream capability".into()))
    }

    pub fn revoke(&self, token: &str) {
        let Some(mut raw) = decode_token(token) else {
            return;
        };
        let digest = token_digest(&raw);
        raw.zeroize();
        self.grants.lock().remove(&digest);
    }

    pub fn revoke_media(&self, media_id: Uuid) {
        self.grants.lock().retain(|_, grant| grant.media_id != media_id);
    }

    pub fn revoke_all(&self) {
        self.grants.lock().clear();
    }
}

fn accept_loop(
    listener: TcpListener,
    port: u16,
    session: Arc<SessionState>,
    gallery: Arc<GalleryRepository>,
    grants: Arc<Mutex<HashMap<[u8; 32], StreamGrant>>>,
) {
    let active = Arc::new(AtomicUsize::new(0));

    loop {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                if !try_acquire_connection(active.as_ref()) {
                    let _ = write_empty_response(&mut stream, "503 Service Unavailable", None, &[]);
                    continue;
                }

                let worker_active = Arc::clone(&active);
                let worker_session = Arc::clone(&session);
                let worker_gallery = Arc::clone(&gallery);
                let worker_grants = Arc::clone(&grants);
                let spawn_result =
                    thread::Builder::new().name("nd-vault-media-stream".into()).spawn(move || {
                        let _permit = ConnectionPermit(worker_active);
                        handle_connection(stream, port, worker_session, worker_gallery, worker_grants);
                    });
                if spawn_result.is_err() {
                    active.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn try_acquire_connection(active: &AtomicUsize) -> bool {
    loop {
        let current = active.load(Ordering::Acquire);
        if current >= MAX_CONNECTIONS {
            return false;
        }
        if active.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return true;
        }
    }
}

struct ConnectionPermit(Arc<AtomicUsize>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct ParsedRequest {
    method: String,
    target: String,
    host: String,
    range: Option<String>,
    origin: Option<String>,
}

fn handle_connection(
    mut stream: TcpStream,
    port: u16,
    session: Arc<SessionState>,
    gallery: Arc<GalleryRepository>,
    grants: Arc<Mutex<HashMap<[u8; 32], StreamGrant>>>,
) {
    if stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECONDS))).is_err()
        || stream.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECONDS))).is_err()
    {
        return;
    }
    let _ = stream.set_nodelay(true);

    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(_) => {
            let _ = write_empty_response(&mut stream, "400 Bad Request", None, &[]);
            return;
        }
    };

    let expected_host = format!("127.0.0.1:{port}");
    if request.host != expected_host {
        let _ = write_empty_response(&mut stream, "400 Bad Request", None, &[]);
        return;
    }
    if !matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        let _ = write_empty_response(
            &mut stream,
            "405 Method Not Allowed",
            None,
            &[("Allow", "GET, HEAD, OPTIONS")],
        );
        return;
    }

    let origin = request.origin.as_deref();
    if origin.is_some_and(|value| !is_allowed_origin(value)) {
        let _ = write_empty_response(&mut stream, "403 Forbidden", None, &[]);
        return;
    }

    let Some((token, media_id)) = parse_target(&request.target) else {
        let _ = write_empty_response(&mut stream, "404 Not Found", origin, &[]);
        return;
    };
    let mut raw_token = match decode_token(token) {
        Some(token) => token,
        None => {
            let _ = write_empty_response(&mut stream, "404 Not Found", origin, &[]);
            return;
        }
    };
    let digest = token_digest(&raw_token);
    raw_token.zeroize();

    if !authorize_grant(grants.as_ref(), &digest, media_id) {
        let _ = write_empty_response(&mut stream, "404 Not Found", origin, &[]);
        return;
    }

    if request.method == "OPTIONS" {
        let _ = write_empty_response(
            &mut stream,
            "204 No Content",
            origin,
            &[
                ("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"),
                ("Access-Control-Allow-Headers", "Range"),
                ("Access-Control-Max-Age", "600"),
            ],
        );
        return;
    }

    let key = match session.domain_key(GALLERY_DOMAIN) {
        Ok(key) => key,
        Err(VaultError::Locked) => {
            let _ = write_empty_response(&mut stream, "423 Locked", origin, &[]);
            return;
        }
        Err(_) => {
            let _ = write_empty_response(&mut stream, "500 Internal Server Error", origin, &[]);
            return;
        }
    };
    let object = match gallery.media_object(media_id) {
        Ok(object) if object.mime_type.starts_with("video/") => object,
        Ok(_) | Err(VaultError::NotFound) => {
            let _ = write_empty_response(&mut stream, "404 Not Found", origin, &[]);
            return;
        }
        Err(_) => {
            let _ = write_empty_response(&mut stream, "500 Internal Server Error", origin, &[]);
            return;
        }
    };
    let mut reader = match ContainerReader::open(&key, object.container_id, &object.path) {
        Ok(reader) => reader,
        Err(VaultError::AuthenticationFailed | VaultError::MalformedContainer) => {
            let _ = write_empty_response(&mut stream, "422 Unprocessable Content", origin, &[]);
            return;
        }
        Err(_) => {
            let _ = write_empty_response(&mut stream, "500 Internal Server Error", origin, &[]);
            return;
        }
    };
    let metadata = reader.metadata().clone();
    if metadata.total_size == 0
        || metadata.mime_type != object.mime_type
        || metadata.total_size != object.total_size
        || !metadata.mime_type.starts_with("video/")
    {
        let _ = write_empty_response(&mut stream, "422 Unprocessable Content", origin, &[]);
        return;
    }

    let (start, end, status) = match request.range.as_deref() {
        Some(value) => match parse_range(value, metadata.total_size) {
            Ok((start, end)) => (start, end, "206 Partial Content"),
            Err(()) => {
                let content_range = format!("bytes */{}", metadata.total_size);
                let _ = write_empty_response(
                    &mut stream,
                    "416 Range Not Satisfiable",
                    origin,
                    &[("Content-Range", content_range.as_str())],
                );
                return;
            }
        },
        None => (0, metadata.total_size - 1, "200 OK"),
    };

    let content_length = end - start + 1;
    let content_length_value = content_length.to_string();
    let content_range_value = if status.starts_with("206") {
        Some(format!("bytes {start}-{end}/{}", metadata.total_size))
    } else {
        None
    };
    let mut headers = vec![
        ("Content-Type", metadata.mime_type.as_str()),
        ("Accept-Ranges", "bytes"),
        ("Content-Length", content_length_value.as_str()),
        ("Access-Control-Expose-Headers", "Accept-Ranges, Content-Length, Content-Range"),
    ];
    if let Some(value) = content_range_value.as_deref() {
        headers.push(("Content-Range", value));
    }

    if write_response_head(&mut stream, status, origin, &headers).is_err() || request.method == "HEAD" {
        return;
    }

    let mut offset = start;
    while offset <= end {
        if session.touch().is_err() || !authorize_grant(grants.as_ref(), &digest, media_id) {
            return;
        }
        let window_end = end.min(offset.saturating_add(STREAM_WINDOW_BYTES - 1));
        let plaintext = match reader.decrypt_range(offset, window_end, STREAM_WINDOW_BYTES) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return,
        };
        if stream.write_all(plaintext.as_slice()).is_err() {
            return;
        }
        offset = match window_end.checked_add(1) {
            Some(next) => next,
            None => return,
        };
    }
    let _ = stream.flush();
}

fn authorize_grant(
    grants: &Mutex<HashMap<[u8; 32], StreamGrant>>,
    digest: &[u8; 32],
    media_id: Uuid,
) -> bool {
    let mut grants = grants.lock();
    let now = Instant::now();
    let Some(grant) = grants.get(digest).copied() else {
        return false;
    };
    if grant.media_id != media_id || grant.expires_at <= now {
        grants.remove(digest);
        return false;
    }
    if let Some(grant) = grants.get_mut(digest) {
        grant.expires_at = now + Duration::from_secs(GRANT_TTL_SECONDS);
        true
    } else {
        false
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<ParsedRequest> {
    let mut buffer = Vec::with_capacity(4096);
    let mut scratch = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP request ended before its headers",
            ));
        }
        buffer.extend_from_slice(&scratch[..read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP request headers are too large",
            ));
        }
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let head = std::str::from_utf8(&buffer[..header_end]).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "HTTP request headers are not UTF-8")
    })?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "HTTP request line is missing")
    })?;
    let mut request_parts = request_line.split_ascii_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let target = request_parts.next().unwrap_or_default();
    let version = request_parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || target.len() > MAX_TARGET_BYTES
        || request_parts.next().is_some()
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
    {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP request line"));
    }

    let mut host = None;
    let mut range = None;
    let mut origin = None;
    let mut content_length = None;
    let mut transfer_encoding = false;

    for line in lines {
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP header line"));
        }
        let (name, raw_value) = line
            .split_once(':')
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP header"))?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP header name"));
        }
        let value = raw_value.trim();
        if name.eq_ignore_ascii_case("host") {
            set_once(&mut host, value, MAX_ORIGIN_BYTES)?;
        } else if name.eq_ignore_ascii_case("range") {
            set_once(&mut range, value, MAX_RANGE_HEADER_BYTES)?;
        } else if name.eq_ignore_ascii_case("origin") {
            set_once(&mut origin, value, MAX_ORIGIN_BYTES)?;
        } else if name.eq_ignore_ascii_case("content-length") {
            set_once(&mut content_length, value, 32)?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = true;
        }
    }

    if transfer_encoding {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request bodies are not supported"));
    }
    if content_length.as_deref().map(|value| value != "0").unwrap_or(false) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request bodies are not supported"));
    }
    let host =
        host.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Host header is required"))?;

    Ok(ParsedRequest { method: method.to_owned(), target: target.to_owned(), host, range, origin })
}

fn set_once(destination: &mut Option<String>, value: &str, maximum_bytes: usize) -> std::io::Result<()> {
    if destination.is_some() || value.is_empty() || value.len() > maximum_bytes {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid or repeated HTTP header"));
    }
    *destination = Some(value.to_owned());
    Ok(())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_target(target: &str) -> Option<(&str, Uuid)> {
    if target.contains('?') || target.contains('%') || target.contains('\\') || target.contains("..") {
        return None;
    }
    let parts: Vec<_> = target.split('/').collect();
    if parts.len() != 5 || !parts[0].is_empty() || parts[1] != "v1" || parts[3] != "media" {
        return None;
    }
    if parts[2].len() != TOKEN_HEX_BYTES {
        return None;
    }
    let id = Uuid::parse_str(parts[4]).ok()?;
    if id.to_string() != parts[4] {
        return None;
    }
    Some((parts[2], id))
}

fn parse_range(value: &str, total: u64) -> std::result::Result<(u64, u64), ()> {
    if total == 0 || !value.starts_with("bytes=") || value.contains(',') {
        return Err(());
    }
    let raw = &value[6..];
    let (left, right) = raw.split_once('-').ok_or(())?;

    if left.is_empty() {
        let suffix = right.parse::<u64>().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        let length = suffix.min(total);
        return Ok((total - length, total - 1));
    }

    let start = left.parse::<u64>().map_err(|_| ())?;
    if start >= total {
        return Err(());
    }
    let end = if right.is_empty() { total - 1 } else { right.parse::<u64>().map_err(|_| ())?.min(total - 1) };
    if end < start {
        return Err(());
    }
    Ok((start, end))
}

fn is_allowed_origin(origin: &str) -> bool {
    matches!(
        origin,
        "tauri://localhost"
            | "http://tauri.localhost"
            | "https://tauri.localhost"
            | "http://localhost:1420"
            | "https://localhost:1420"
            | "null"
    )
}

fn write_response_head(
    stream: &mut TcpStream,
    status: &str,
    origin: Option<&str>,
    headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nCache-Control: no-store, private, max-age=0\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n"
    );
    if let Some(origin) = origin {
        response.push_str("Access-Control-Allow-Origin: ");
        response.push_str(origin);
        response.push_str("\r\nVary: Origin\r\n");
    }
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes())
}

fn write_empty_response(
    stream: &mut TcpStream,
    status: &str,
    origin: Option<&str>,
    headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut combined = Vec::with_capacity(headers.len() + 1);
    combined.extend_from_slice(headers);
    combined.push(("Content-Length", "0"));
    write_response_head(stream, status, origin, &combined)
}

fn encode_token(raw: &[u8; TOKEN_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(TOKEN_HEX_BYTES);
    for byte in raw {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_token(value: &str) -> Option<[u8; TOKEN_BYTES]> {
    if value.len() != TOKEN_HEX_BYTES || !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    let mut output = [0_u8; TOKEN_BYTES];
    for (index, destination) in output.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *destination = (high << 4) | low;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn token_digest(raw: &[u8; TOKEN_BYTES]) -> [u8; 32] {
    let digest = Sha256::digest(raw);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_encoding_round_trips() {
        let raw = [0xab_u8; TOKEN_BYTES];
        let encoded = encode_token(&raw);
        assert_eq!(encoded.len(), TOKEN_HEX_BYTES);
        assert_eq!(decode_token(&encoded), Some(raw));
        assert!(decode_token(&encoded.to_uppercase()).is_none());
    }

    #[test]
    fn parses_strict_media_target() {
        let id = Uuid::new_v4();
        let token = "00".repeat(TOKEN_BYTES);
        let target = format!("/v1/{token}/media/{id}");
        let parsed = parse_target(&target).unwrap();
        assert_eq!(parsed.0, token);
        assert_eq!(parsed.1, id);
        assert!(parse_target(&(target + "?x=1")).is_none());
    }

    #[test]
    fn parses_closed_open_and_suffix_ranges() {
        assert_eq!(parse_range("bytes=10-19", 100).unwrap(), (10, 19));
        assert_eq!(parse_range("bytes=90-", 100).unwrap(), (90, 99));
        assert_eq!(parse_range("bytes=-10", 100).unwrap(), (90, 99));
        assert!(parse_range("bytes=0-1,4-5", 100).is_err());
        assert!(parse_range("bytes=100-", 100).is_err());
    }
}
