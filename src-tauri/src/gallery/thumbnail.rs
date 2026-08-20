use std::{
    io::{Cursor, Read},
    panic::{catch_unwind, AssertUnwindSafe},
};

use image::{
    metadata::Orientation, DynamicImage, GenericImageView, ImageDecoder, ImageFormat, ImageReader, Limits,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "android")]
pub const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
pub const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "android")]
const MAX_DECODE_ALLOC_BYTES: u64 = 128 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_DECODE_ALLOC_BYTES: u64 = 256 * 1024 * 1024;

const MAX_IMAGE_DIMENSION: u32 = 32_768;
const MAX_DECODE_BYTES_PER_PIXEL: u64 = 8;
const THUMBNAIL_EDGE: u32 = 512;
const MAX_THUMBNAIL_BYTES: usize = 4 * 1024 * 1024;
const THUMBNAIL_ID_DOMAIN: &[u8] = b"nd-secure/gallery-thumbnail-id/v1";

pub struct ThumbnailCapture<'a, R: Read> {
    inner: &'a mut R,
    total_size: u64,
    captured: Option<Zeroizing<Vec<u8>>>,
}

impl<'a, R: Read> ThumbnailCapture<'a, R> {
    pub fn new(inner: &'a mut R, total_size: u64) -> Self {
        let captured = (total_size <= MAX_SOURCE_BYTES)
            .then_some(())
            .and_then(|_| usize::try_from(total_size).ok())
            .map(|_| Zeroizing::new(Vec::new()));
        Self { inner, total_size, captured }
    }

    pub fn finish(self) -> Option<Zeroizing<Vec<u8>>> {
        self.captured.filter(|bytes| bytes.len() as u64 == self.total_size && is_image_signature(bytes))
    }
}

impl<R: Read> Read for ThumbnailCapture<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read == 0 {
            return Ok(0);
        }

        if let Some(captured) = self.captured.as_mut() {
            let previous_len = captured.len();
            let Some(next_len) = previous_len.checked_add(read) else {
                self.captured = None;
                return Ok(read);
            };
            if next_len as u64 > self.total_size {
                self.captured = None;
                return Ok(read);
            }

            captured.extend_from_slice(&buffer[..read]);
            if captured.len() >= 12 {
                if !is_image_signature(captured) {
                    self.captured = None;
                } else if previous_len < 12 {
                    let remaining = usize::try_from(self.total_size)
                        .ok()
                        .and_then(|total| total.checked_sub(captured.len()));
                    if remaining.and_then(|additional| captured.try_reserve_exact(additional).ok()).is_none()
                    {
                        self.captured = None;
                    }
                }
            }
        }
        Ok(read)
    }
}

pub struct GeneratedThumbnail {
    pub bytes: Zeroizing<Vec<u8>>,
    pub source_width: u32,
    pub source_height: u32,
}

pub fn generate_thumbnail(source: Zeroizing<Vec<u8>>, mime_type: &str) -> Option<GeneratedThumbnail> {
    catch_unwind(AssertUnwindSafe(|| generate_thumbnail_inner(source, mime_type))).ok().flatten()
}

fn generate_thumbnail_inner(source: Zeroizing<Vec<u8>>, mime_type: &str) -> Option<GeneratedThumbnail> {
    let format = match mime_type {
        "image/jpeg" => ImageFormat::Jpeg,
        "image/png" => ImageFormat::Png,
        _ => return None,
    };

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC_BYTES);

    let mut reader = ImageReader::with_format(Cursor::new(source.as_slice()), format);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().ok()?;
    let (encoded_width, encoded_height) = decoder.dimensions();
    let decoded_upper_bound = u64::from(encoded_width)
        .checked_mul(u64::from(encoded_height))?
        .checked_mul(MAX_DECODE_BYTES_PER_PIXEL)?;
    let decoder_reported_bytes = decoder.total_bytes();
    if encoded_width == 0
        || encoded_height == 0
        || encoded_width > MAX_IMAGE_DIMENSION
        || encoded_height > MAX_IMAGE_DIMENSION
        || decoded_upper_bound > MAX_DECODE_ALLOC_BYTES
        || decoder_reported_bytes == 0
        || decoder_reported_bytes > MAX_DECODE_ALLOC_BYTES
    {
        return None;
    }
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);

    let decoded = SensitiveImage::new(DynamicImage::from_decoder(decoder).ok()?);
    if decoded.dimensions() != (encoded_width, encoded_height) {
        return None;
    }

    let mut thumbnail = SensitiveImage::new(decoded.thumbnail(THUMBNAIL_EDGE, THUMBNAIL_EDGE));
    drop(decoded);
    thumbnail.apply_orientation(orientation);
    let (source_width, source_height) = oriented_dimensions(encoded_width, encoded_height, orientation);

    let mut encoded = Zeroizing::new(Vec::new());
    {
        let mut destination = Cursor::new(&mut *encoded);
        thumbnail.write_to(&mut destination, ImageFormat::Png).ok()?;
    }
    drop(thumbnail);

    if encoded.is_empty() || encoded.len() > MAX_THUMBNAIL_BYTES {
        return None;
    }
    Some(GeneratedThumbnail { bytes: encoded, source_width, source_height })
}

struct SensitiveImage(DynamicImage);

impl SensitiveImage {
    fn new(image: DynamicImage) -> Self {
        Self(image)
    }

    fn dimensions(&self) -> (u32, u32) {
        self.0.dimensions()
    }

    fn thumbnail(&self, width: u32, height: u32) -> DynamicImage {
        let (source_width, source_height) = self.0.dimensions();
        self.0.thumbnail(width.min(source_width), height.min(source_height))
    }

    fn apply_orientation(&mut self, orientation: Orientation) {
        self.0.apply_orientation(orientation);
    }

    fn write_to<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        format: ImageFormat,
    ) -> image::ImageResult<()> {
        self.0.write_to(writer, format)
    }
}

impl Drop for SensitiveImage {
    fn drop(&mut self) {
        zeroize_image(&mut self.0);
    }
}

fn oriented_dimensions(width: u32, height: u32, orientation: Orientation) -> (u32, u32) {
    match orientation {
        Orientation::Rotate90
        | Orientation::Rotate270
        | Orientation::Rotate90FlipH
        | Orientation::Rotate270FlipH => (height, width),
        _ => (width, height),
    }
}

pub fn thumbnail_container_id(media_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(THUMBNAIL_ID_DOMAIN);
    hasher.update(media_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn is_image_signature(bytes: &[u8]) -> bool {
    (bytes.len() >= 3 && bytes[..3] == [0xff, 0xd8, 0xff])
        || (bytes.len() >= 8 && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a])
}

fn zeroize_image(image: &mut DynamicImage) {
    if let Some(buffer) = image.as_mut_luma8() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_luma_alpha8() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_rgb8() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_rgba8() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_luma16() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_luma_alpha16() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_rgb16() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_rgba16() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_rgb32f() {
        buffer.as_mut().zeroize();
    } else if let Some(buffer) = image.as_mut_rgba32f() {
        buffer.as_mut().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbnail_ids_are_deterministic_and_domain_separated() {
        let media = Uuid::new_v4();
        let first = thumbnail_container_id(media);
        let second = thumbnail_container_id(media);
        assert_eq!(first, second);
        assert_ne!(first, media);
    }

    #[test]
    fn capture_keeps_images_and_discards_video() {
        let mut jpeg = Cursor::new(vec![0xff, 0xd8, 0xff, 0x00, 0x01, 0x02]);
        let mut capture = ThumbnailCapture::new(&mut jpeg, 6);
        let mut output = Vec::new();
        capture.read_to_end(&mut output).unwrap();
        assert!(capture.finish().is_some());

        let mut mp4 = Cursor::new(b"\0\0\0\x18ftypisommore".to_vec());
        let size = mp4.get_ref().len() as u64;
        let mut capture = ThumbnailCapture::new(&mut mp4, size);
        let mut output = Vec::new();
        capture.read_to_end(&mut output).unwrap();
        assert!(capture.finish().is_none());
    }

    #[test]
    fn malformed_image_is_rejected_without_escaping_the_boundary() {
        let malformed = Zeroizing::new(vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 1, 2, 3]);
        assert!(generate_thumbnail(malformed, "image/png").is_none());
    }

    #[test]
    fn rotated_orientations_swap_reported_dimensions() {
        assert_eq!(oriented_dimensions(640, 480, Orientation::Rotate90), (480, 640));
        assert_eq!(oriented_dimensions(640, 480, Orientation::Rotate270FlipH), (480, 640));
        assert_eq!(oriented_dimensions(640, 480, Orientation::FlipHorizontal), (640, 480));
    }

    #[test]
    fn generates_bounded_png_thumbnail() {
        let source = DynamicImage::new_rgb8(1_024, 768);
        let mut encoded = Cursor::new(Vec::new());
        source.write_to(&mut encoded, ImageFormat::Png).unwrap();

        let generated = generate_thumbnail(Zeroizing::new(encoded.into_inner()), "image/png").unwrap();
        assert_eq!((generated.source_width, generated.source_height), (1_024, 768));
        assert!(generated.bytes.len() <= MAX_THUMBNAIL_BYTES);

        let dimensions = ImageReader::with_format(Cursor::new(generated.bytes.as_slice()), ImageFormat::Png)
            .into_dimensions()
            .unwrap();
        assert_eq!(dimensions, (512, 384));
    }
}
