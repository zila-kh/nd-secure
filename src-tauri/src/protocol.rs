use tauri::http::{
    header::{
        ACCEPT_RANGES, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
        ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
        ORIGIN, RANGE, VARY,
    },
    Method, Request, Response, StatusCode,
};
use uuid::Uuid;

use crate::{
    crypto::GALLERY_DOMAIN,
    error::VaultError,
    gallery::ContainerReader,
    state::AppState,
};

#[cfg(target_os = "android")]
const MAX_RANGE_BYTES: u64 = 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_RANGE_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(target_os = "android")]
const MAX_COMPLETE_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_COMPLETE_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

pub fn response(state: &AppState, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
    let origin = match checked_origin(&request) {
        Ok(origin) => origin,
        Err(status) => return empty_response(status, None),
    };

    if request.method() == Method::OPTIONS {
        return preflight_response(origin.as_deref());
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED, origin.as_deref());
    }

    let Some(_permit) = state.try_protocol_permit() else {
        return empty_response(StatusCode::SERVICE_UNAVAILABLE, origin.as_deref());
    };

    match media_response(state, &request, origin.as_deref()) {
        Ok(response) => response,
        Err(error) => error_response(error, origin.as_deref()),
    }
}

fn media_response(
    state: &AppState,
    request: &Request<Vec<u8>>,
    origin: Option<&str>,
) -> Result<Response<Vec<u8>>, VaultError> {
    let id = parse_media_id(request)?;
    let key = state.session.domain_key(GALLERY_DOMAIN)?;
    let item = state.gallery.get(id)?;
    let object_path = state.gallery.object_path(id)?;
    let mut reader = ContainerReader::open(&key, id, &object_path)?;
    let metadata = reader.metadata().clone();

    if metadata.mime_type != item.mime_type || metadata.total_size != item.file_size_bytes {
        return Err(VaultError::AuthenticationFailed);
    }

    let requested_range = request
        .headers()
        .get(RANGE)
        .map(|value| value.to_str().map_err(|_| VaultError::InvalidRange))
        .transpose()?;

    let (start, end, status) = if let Some(value) = requested_range {
        let (start, mut end) = match parse_range(value, metadata.total_size) {
            Ok(range) => range,
            Err(RangeIssue::Malformed) => {
                return Ok(empty_response(StatusCode::BAD_REQUEST, origin));
            }
            Err(RangeIssue::Unsatisfiable) => {
                return Ok(range_error_response(metadata.total_size, origin));
            }
        };
        end = end.min(
            start
                .checked_add(MAX_RANGE_BYTES - 1)
                .ok_or(VaultError::InvalidRange)?,
        );
        (start, end, StatusCode::PARTIAL_CONTENT)
    } else if metadata.total_size <= MAX_COMPLETE_IMAGE_BYTES {
        (0, metadata.total_size - 1, StatusCode::OK)
    } else if metadata.mime_type.starts_with("video/") {
        (
            0,
            (metadata.total_size - 1).min(MAX_RANGE_BYTES - 1),
            StatusCode::PARTIAL_CONTENT,
        )
    } else {
        return Err(VaultError::RangeTooLarge);
    };

    let response_length = end
        .checked_sub(start)
        .and_then(|value| value.checked_add(1))
        .ok_or(VaultError::InvalidRange)?;
    let body = if request.method() == Method::HEAD {
        Vec::new()
    } else {
        reader.decrypt_range(start, end, response_length)?
    };

    let mut builder = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, metadata.mime_type)
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, response_length.to_string())
        .header(CACHE_CONTROL, "no-store, private, max-age=0")
        .header("Pragma", "no-cache")
        .header("X-Content-Type-Options", "nosniff");

    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            CONTENT_RANGE,
            format!("bytes {start}-{end}/{}", metadata.total_size),
        );
    }
    if let Some(origin) = origin {
        builder = builder
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, origin)
            .header(VARY, "Origin");
    }
    builder
        .body(body)
        .map_err(|_| VaultError::Platform("unable to construct media response".into()))
}

fn parse_media_id(request: &Request<Vec<u8>>) -> Result<Uuid, VaultError> {
    if request.uri().query().is_some() {
        return Err(VaultError::InvalidInput("media URL must not contain a query".into()));
    }
    let path = request.uri().path();
    if path.contains('%') || path.contains('\\') || path.contains("..") {
        return Err(VaultError::InvalidInput("invalid media URL".into()));
    }
    let id = path
        .strip_prefix("/media/")
        .filter(|value| !value.is_empty() && !value.contains('/'))
        .ok_or(VaultError::NotFound)?;
    let parsed = Uuid::parse_str(id).map_err(|_| VaultError::NotFound)?;
    if parsed.to_string() != id {
        return Err(VaultError::NotFound);
    }
    Ok(parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeIssue {
    Malformed,
    Unsatisfiable,
}

fn parse_range(value: &str, total: u64) -> std::result::Result<(u64, u64), RangeIssue> {
    if total == 0 || !value.starts_with("bytes=") || value.contains(',') {
        return Err(RangeIssue::Malformed);
    }
    let raw = &value[6..];
    let (left, right) = raw.split_once('-').ok_or(RangeIssue::Malformed)?;

    if left.is_empty() {
        let suffix = right.parse::<u64>().map_err(|_| RangeIssue::Malformed)?;
        if suffix == 0 {
            return Err(RangeIssue::Unsatisfiable);
        }
        let length = suffix.min(total);
        return Ok((total - length, total - 1));
    }

    let start = left.parse::<u64>().map_err(|_| RangeIssue::Malformed)?;
    if start >= total {
        return Err(RangeIssue::Unsatisfiable);
    }
    let end = if right.is_empty() {
        total - 1
    } else {
        right
            .parse::<u64>()
            .map_err(|_| RangeIssue::Malformed)?
            .min(total - 1)
    };
    if end < start {
        return Err(RangeIssue::Unsatisfiable);
    }
    Ok((start, end))
}

fn checked_origin(request: &Request<Vec<u8>>) -> Result<Option<String>, StatusCode> {
    let Some(value) = request.headers().get(ORIGIN) else {
        return Ok(None);
    };
    let origin = value.to_str().map_err(|_| StatusCode::FORBIDDEN)?;
    if is_allowed_origin(origin) {
        Ok(Some(origin.to_owned()))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn is_allowed_origin(origin: &str) -> bool {
    matches!(
        origin,
        "tauri://localhost"
            | "http://tauri.localhost"
            | "https://tauri.localhost"
            | "http://localhost:1420"
            | "https://localhost:1420"
    )
}

fn preflight_response(origin: Option<&str>) -> Response<Vec<u8>> {
    let mut builder = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, OPTIONS")
        .header(ACCESS_CONTROL_ALLOW_HEADERS, "Range")
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_LENGTH, "0");
    if let Some(origin) = origin {
        builder = builder
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, origin)
            .header(VARY, "Origin");
    }
    builder.body(Vec::new()).unwrap_or_else(|_| Response::new(Vec::new()))
}


fn range_error_response(total: u64, origin: Option<&str>) -> Response<Vec<u8>> {
    let mut builder = Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(CONTENT_RANGE, format!("bytes */{total}"))
        .header(CACHE_CONTROL, "no-store, private, max-age=0")
        .header(CONTENT_LENGTH, "0")
        .header("X-Content-Type-Options", "nosniff");
    if let Some(origin) = origin {
        builder = builder
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, origin)
            .header(VARY, "Origin");
    }
    builder.body(Vec::new()).unwrap_or_else(|_| Response::new(Vec::new()))
}

fn error_response(error: VaultError, origin: Option<&str>) -> Response<Vec<u8>> {
    let status = match error {
        VaultError::Locked => StatusCode::from_u16(423).unwrap_or(StatusCode::UNAUTHORIZED),
        VaultError::NotFound => StatusCode::NOT_FOUND,
        VaultError::InvalidRange => StatusCode::RANGE_NOT_SATISFIABLE,
        VaultError::RangeTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        VaultError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        VaultError::AuthenticationFailed
        | VaultError::MalformedContainer
        | VaultError::UnsupportedMedia => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    empty_response(status, origin)
}

fn empty_response(status: StatusCode, origin: Option<&str>) -> Response<Vec<u8>> {
    let mut builder = Response::builder()
        .status(status)
        .header(CACHE_CONTROL, "no-store, private, max-age=0")
        .header(CONTENT_LENGTH, "0")
        .header("X-Content-Type-Options", "nosniff");
    if let Some(origin) = origin {
        builder = builder
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, origin)
            .header(VARY, "Origin");
    }
    builder.body(Vec::new()).unwrap_or_else(|_| Response::new(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_closed_open_and_suffix_ranges() {
        assert_eq!(parse_range("bytes=10-19", 100).unwrap(), (10, 19));
        assert_eq!(parse_range("bytes=90-", 100).unwrap(), (90, 99));
        assert_eq!(parse_range("bytes=-10", 100).unwrap(), (90, 99));
    }

    #[test]
    fn rejects_multiple_or_unsatisfied_ranges() {
        assert_eq!(parse_range("bytes=0-1,4-5", 100), Err(RangeIssue::Malformed));
        assert_eq!(parse_range("bytes=100-", 100), Err(RangeIssue::Unsatisfiable));
        assert_eq!(parse_range("items=0-1", 100), Err(RangeIssue::Malformed));
    }
}
