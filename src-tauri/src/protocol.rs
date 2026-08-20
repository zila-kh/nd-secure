use tauri::http::{
    header::{
        ACCEPT_RANGES, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
        ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ORIGIN,
        RANGE, VARY,
    },
    Method, Request, Response, StatusCode,
};
use uuid::Uuid;

use crate::{
    crypto::GALLERY_DOMAIN,
    error::VaultError,
    gallery::{ContainerReader, GalleryObject},
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

const MAX_THUMBNAIL_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectKind {
    Media,
    Thumbnail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectTarget {
    kind: ObjectKind,
    media_id: Uuid,
}

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

    match object_response(state, &request, origin.as_deref()) {
        Ok(response) => response,
        Err(error) => error_response(error, origin.as_deref()),
    }
}

fn object_response(
    state: &AppState,
    request: &Request<Vec<u8>>,
    origin: Option<&str>,
) -> Result<Response<Vec<u8>>, VaultError> {
    let target = parse_object_target(request)?;
    let key = state.session.domain_key(GALLERY_DOMAIN)?;
    let object = match target.kind {
        ObjectKind::Media => state.gallery.media_object(target.media_id)?,
        ObjectKind::Thumbnail => match state.gallery.thumbnail_object(target.media_id) {
            Ok(object) => object,
            Err(VaultError::NotFound) => {
                if !state.gallery.ensure_thumbnail(&key, target.media_id)? {
                    return Err(VaultError::NotFound);
                }
                state.gallery.thumbnail_object(target.media_id)?
            }
            Err(error) => return Err(error),
        },
    };
    validate_object_bounds(target.kind, &object)?;

    let mut reader = ContainerReader::open(&key, object.container_id, &object.path)?;
    let metadata = reader.metadata().clone();
    if metadata.mime_type != object.mime_type || metadata.total_size != object.total_size {
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
        end = end.min(start.checked_add(MAX_RANGE_BYTES - 1).ok_or(VaultError::InvalidRange)?);
        (start, end, StatusCode::PARTIAL_CONTENT)
    } else {
        complete_response_range(target.kind, &metadata.mime_type, metadata.total_size)?
    };

    let response_length =
        end.checked_sub(start).and_then(|value| value.checked_add(1)).ok_or(VaultError::InvalidRange)?;
    let body = if request.method() == Method::HEAD {
        Vec::new()
    } else {
        reader.decrypt_range(start, end, response_length)?
    };

    let mut builder = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, metadata.mime_type.as_str())
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, response_length.to_string())
        .header(CACHE_CONTROL, "no-store, private, max-age=0")
        .header("Pragma", "no-cache")
        .header("X-Content-Type-Options", "nosniff");

    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{}", metadata.total_size));
    }
    if let Some(origin) = origin {
        builder = builder.header(ACCESS_CONTROL_ALLOW_ORIGIN, origin).header(VARY, "Origin");
    }
    builder.body(body).map_err(|_| VaultError::Platform("unable to construct media response".into()))
}

fn validate_object_bounds(kind: ObjectKind, object: &GalleryObject) -> Result<(), VaultError> {
    if object.total_size == 0 {
        return Err(VaultError::AuthenticationFailed);
    }
    if kind == ObjectKind::Thumbnail
        && (object.mime_type != "image/png" || object.total_size > MAX_THUMBNAIL_BYTES)
    {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(())
}

fn complete_response_range(
    kind: ObjectKind,
    mime_type: &str,
    total_size: u64,
) -> Result<(u64, u64, StatusCode), VaultError> {
    if kind == ObjectKind::Thumbnail {
        if total_size > MAX_THUMBNAIL_BYTES {
            return Err(VaultError::RangeTooLarge);
        }
        return Ok((0, total_size - 1, StatusCode::OK));
    }
    if total_size <= MAX_COMPLETE_IMAGE_BYTES {
        return Ok((0, total_size - 1, StatusCode::OK));
    }
    if mime_type.starts_with("video/") {
        return Ok((0, (total_size - 1).min(MAX_RANGE_BYTES - 1), StatusCode::PARTIAL_CONTENT));
    }
    Err(VaultError::RangeTooLarge)
}

fn parse_object_target(request: &Request<Vec<u8>>) -> Result<ObjectTarget, VaultError> {
    if request.uri().query().is_some() {
        return Err(VaultError::InvalidInput("vault URL must not contain a query".into()));
    }
    let path = request.uri().path();
    if path.contains('%') || path.contains('\\') || path.contains("..") {
        return Err(VaultError::InvalidInput("invalid vault URL".into()));
    }
    let (kind, id) = if let Some(id) = path.strip_prefix("/media/") {
        (ObjectKind::Media, id)
    } else if let Some(id) = path.strip_prefix("/thumbnail/") {
        (ObjectKind::Thumbnail, id)
    } else {
        return Err(VaultError::NotFound);
    };
    if id.is_empty() || id.contains('/') {
        return Err(VaultError::NotFound);
    }
    let media_id = Uuid::parse_str(id).map_err(|_| VaultError::NotFound)?;
    if media_id.to_string() != id {
        return Err(VaultError::NotFound);
    }
    Ok(ObjectTarget { kind, media_id })
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
        right.parse::<u64>().map_err(|_| RangeIssue::Malformed)?.min(total - 1)
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
        builder = builder.header(ACCESS_CONTROL_ALLOW_ORIGIN, origin).header(VARY, "Origin");
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
        builder = builder.header(ACCESS_CONTROL_ALLOW_ORIGIN, origin).header(VARY, "Origin");
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
        VaultError::AuthenticationFailed | VaultError::MalformedContainer | VaultError::UnsupportedMedia => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
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
        builder = builder.header(ACCESS_CONTROL_ALLOW_ORIGIN, origin).header(VARY, "Origin");
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

    #[test]
    fn parses_media_and_thumbnail_routes() {
        let id = Uuid::new_v4();
        let media = Request::builder().uri(format!("/media/{id}")).body(Vec::new()).unwrap();
        let thumbnail = Request::builder().uri(format!("/thumbnail/{id}")).body(Vec::new()).unwrap();
        assert_eq!(parse_object_target(&media).unwrap().kind, ObjectKind::Media);
        assert_eq!(parse_object_target(&thumbnail).unwrap().kind, ObjectKind::Thumbnail);
    }
}
