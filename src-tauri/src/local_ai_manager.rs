//! Local AI Post-Install Model Manager for Tauri 2
//!
//! Manages lifecycle, resumable streaming download, SHA-256 verification,
//! cancellation, and removal for the `gpt-oss-20b` model.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};

pub const MODEL_NAME: &str = "gpt-oss-20b";
pub const MODEL_URL: &str =
    "https://huggingface.co/ggml-org/gpt-oss-20b-GGUF/resolve/main/gpt-oss-20b-MXFP4.gguf";
pub const EXPECTED_SHA256: &str =
    "27cd6c432c7672cb812a92f611cf3ba7bbc35928262bb1e1253ff4ee6ae35901";
pub const EXPECTED_MODEL_BYTES: u64 = 12_109_566_624;
pub const PUBLISHED_SIZE_DISPLAY: &str = "12.1 GB";
pub const MODEL_LICENSE: &str = "Apache-2.0";

pub const FINAL_FILENAME: &str = "gpt-oss-20b-MXFP4.gguf";
pub const PARTIAL_FILENAME: &str = "gpt-oss-20b-MXFP4.gguf.part";

// reqwest 0.12's blocking client exposes a total request timeout rather than an
// idle-read timeout. The model is 12.1 GB, so a short timeout would make every
// real download fail even while bytes are arriving. Keep a finite upper bound
// that accommodates slow links; cooperative cancellation is checked between
// streamed reads.
const DOWNLOAD_REQUEST_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Status lifecycle for the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelStatus {
    NotInstalled,
    Partial,
    Downloading,
    Verifying,
    Installed,
    Corrupt,
}

/// Status payload returned to frontend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalAiModelStatus {
    pub name: String,
    pub status: ModelStatus,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub model_path: Option<String>,
    pub error_message: Option<String>,
    pub license: String,
    pub published_size: String,
}

/// Progress event payload emitted to frontend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalAiDownloadProgress {
    pub status: ModelStatus,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub percent: f64,
}

/// Content-Range parse result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
    pub total: u64,
}

/// Resume decision resolved from HTTP response headers and status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeDecision {
    AppendValidRange { start_byte: u64, total_bytes: u64 },
    RequiresFreshRestart { reason: String },
    FatalError { status_code: u16, message: String },
}

// Global atomic flags and operation sequencing for concurrency and cooperative cancellation
static CURRENT_DOWNLOAD_ID: AtomicU64 = AtomicU64::new(0);
static ACTIVE_DOWNLOAD: AtomicBool = AtomicBool::new(false);
static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static IS_VERIFYING: AtomicBool = AtomicBool::new(false);
static DOWNLOAD_CONTROL: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone)]
struct VerifiedCacheEntry {
    file_path: PathBuf,
    file_len: u64,
    modified_time: Option<SystemTime>,
    is_valid: bool,
}

static VERIFIED_CACHE: Mutex<Option<VerifiedCacheEntry>> = Mutex::new(None);
static VERIFY_MUTEX: Mutex<()> = Mutex::new(());

/// Guard ensuring ACTIVE_DOWNLOAD and CANCEL_REQUESTED are reset when the blocking worker finishes,
/// tied to a specific operation ID so it never clears a newer operation's state.
pub struct DownloadGuard {
    pub op_id: u64,
}

impl Drop for DownloadGuard {
    fn drop(&mut self) {
        let _control = match DOWNLOAD_CONTROL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if CURRENT_DOWNLOAD_ID.load(Ordering::SeqCst) == self.op_id {
            ACTIVE_DOWNLOAD.store(false, Ordering::SeqCst);
            CANCEL_REQUESTED.store(false, Ordering::SeqCst);
        }
    }
}

struct VerifyingGuard;

impl Drop for VerifyingGuard {
    fn drop(&mut self) {
        IS_VERIFYING.store(false, Ordering::SeqCst);
    }
}

/// Clears any cached verification result.
pub fn clear_verified_cache() {
    if let Ok(mut guard) = VERIFIED_CACHE.lock() {
        *guard = None;
    }
}

/// Resolves the dedicated storage directory for this model under app local data.
pub fn get_model_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let local_data = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Failed to resolve app local data directory: {e}"))?;
    Ok(local_data.join("models").join(MODEL_NAME))
}

/// Rejects a model directory that is a symlink or another non-directory file.
/// A missing directory is allowed so status/removal calls can report a clean
/// not-installed state without creating data on disk.
pub fn validate_model_directory(model_dir: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(model_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "Security check failed: model directory {} is a symbolic link.",
                    model_dir.display()
                ));
            }
            if !metadata.file_type().is_dir() {
                return Err(format!(
                    "Security check failed: model directory {} is not a directory.",
                    model_dir.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "Failed reading model directory metadata for {}: {error}",
            model_dir.display()
        )),
    }
}

/// Validates that a path is strictly inside expected model directory and matches
/// either the final or partial model filename.
pub fn is_exact_model_file(path: &Path, expected_model_dir: &Path) -> bool {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    if file_name != FINAL_FILENAME && file_name != PARTIAL_FILENAME {
        return false;
    }

    match path.parent() {
        Some(parent) => parent == expected_model_dir,
        None => false,
    }
}

/// Hardened check using `symlink_metadata`:
/// - Confirms path is exact expected final or partial model file in `expected_model_dir`.
/// - Rejects symbolic links.
/// - Rejects directories, devices, or non-regular files.
/// - Returns `Ok(Some(len))` if existing regular file, `Ok(None)` if not found, or `Err`.
pub fn validate_regular_model_file(
    path: &Path,
    expected_model_dir: &Path,
) -> Result<Option<u64>, String> {
    if !is_exact_model_file(path, expected_model_dir) {
        return Err(format!(
            "Security check failed: path {} is not an authorized model file in {}",
            path.display(),
            expected_model_dir.display()
        ));
    }

    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "Security check failed: {} is a symbolic link, which is strictly prohibited.",
                    path.display()
                ));
            }
            if !file_type.is_file() {
                return Err(format!(
                    "Security check failed: {} is not a regular file.",
                    path.display()
                ));
            }
            Ok(Some(meta.len()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "Failed reading metadata for {}: {e}",
            path.display()
        )),
    }
}

/// Streams a file through SHA-256 in 256 KB chunks without buffering the file in memory.
pub fn compute_file_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file for hashing ({}): {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 256 * 1024];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed reading file for hashing ({}): {e}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let digest = hasher.finalize();
    Ok(format!("{digest:x}"))
}

/// Parses and validates the HTTP `Content-Range` header value against expected resume start and total size.
pub fn parse_content_range(
    header_val: &str,
    expected_start: u64,
    expected_total: u64,
) -> Result<ContentRange, String> {
    let trimmed = header_val.trim();
    let stripped = trimmed
        .strip_prefix("bytes ")
        .or_else(|| trimmed.strip_prefix("bytes="))
        .ok_or_else(|| "Content-Range header missing 'bytes ' prefix".to_string())?
        .trim();

    let (range_part, total_part) = stripped
        .split_once('/')
        .ok_or_else(|| "Content-Range header missing '/' delimiter".to_string())?;

    let (start_str, end_str) = range_part
        .split_once('-')
        .ok_or_else(|| "Content-Range header missing '-' delimiter".to_string())?;

    let start = start_str
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("Invalid Content-Range start byte '{start_str}': {e}"))?;

    let end = end_str
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("Invalid Content-Range end byte '{end_str}': {e}"))?;

    if end < start {
        return Err(format!(
            "Content-Range end ({end}) cannot be less than start ({start})"
        ));
    }

    if start != expected_start {
        return Err(format!(
            "Content-Range start ({start}) does not match expected resume offset ({expected_start})"
        ));
    }

    if total_part.trim() == "*" {
        return Err(
            "Content-Range wildcard total is not permitted for exact artifact verification"
                .to_string(),
        );
    }

    let total = total_part
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("Invalid Content-Range total length '{total_part}': {e}"))?;

    if total != expected_total {
        return Err(format!(
            "Content-Range total ({total}) does not match expected artifact size ({expected_total})"
        ));
    }

    if end >= total {
        return Err(format!(
            "Content-Range end ({end}) must be strictly less than total size ({total})"
        ));
    }

    Ok(ContentRange { start, end, total })
}

/// Resolves the resume decision from the first HTTP response.
pub fn resolve_resume_decision(
    status_code: u16,
    content_range_hdr: Option<&str>,
    content_len_hdr: Option<u64>,
    existing_len: u64,
    expected_total: u64,
) -> ResumeDecision {
    if existing_len == 0 {
        if status_code == 200 {
            if let Some(cl) = content_len_hdr {
                if cl != expected_total {
                    return ResumeDecision::FatalError {
                        status_code,
                        message: format!(
                            "Content-Length ({cl}) does not match expected model size ({expected_total})"
                        ),
                    };
                }
            }
            return ResumeDecision::RequiresFreshRestart {
                reason: "Initial download from byte zero".to_string(),
            };
        } else if status_code == 206 {
            if let Some(hdr) = content_range_hdr {
                if let Ok(cr) = parse_content_range(hdr, 0, expected_total) {
                    return ResumeDecision::AppendValidRange {
                        start_byte: cr.start,
                        total_bytes: expected_total,
                    };
                }
            }
            return ResumeDecision::RequiresFreshRestart {
                reason: "Initial download 206 requires fresh restart".to_string(),
            };
        } else {
            return ResumeDecision::FatalError {
                status_code,
                message: format!("Download failed with unexpected HTTP status {status_code}"),
            };
        }
    }

    match status_code {
        206 => match content_range_hdr {
            Some(hdr) => match parse_content_range(hdr, existing_len, expected_total) {
                Ok(range) => {
                    if let Some(cl) = content_len_hdr {
                        let expected_remaining = expected_total.saturating_sub(existing_len);
                        if cl != expected_remaining {
                            return ResumeDecision::RequiresFreshRestart {
                                reason: format!(
                                    "Content-Length ({cl}) does not match expected remaining bytes ({expected_remaining})"
                                ),
                            };
                        }
                    }
                    ResumeDecision::AppendValidRange {
                        start_byte: range.start,
                        total_bytes: expected_total,
                    }
                }
                Err(e) => ResumeDecision::RequiresFreshRestart {
                    reason: format!("Mismatched or invalid Content-Range: {e}"),
                },
            },
            None => ResumeDecision::RequiresFreshRestart {
                reason: "HTTP 206 response missing Content-Range header".to_string(),
            },
        },
        200 => ResumeDecision::RequiresFreshRestart {
            reason: "Server returned HTTP 200 to Range request; ignoring body and restarting fresh"
                .to_string(),
        },
        416 => ResumeDecision::RequiresFreshRestart {
            reason: "Server returned HTTP 416 Range Not Satisfiable; restarting fresh".to_string(),
        },
        other => ResumeDecision::FatalError {
            status_code: other,
            message: format!("Download request failed with HTTP status {other}"),
        },
    }
}

/// Validates a replacement response issued without a Range header.
pub fn validate_fresh_response(
    response: &reqwest::blocking::Response,
    expected_bytes: u64,
) -> Result<(), String> {
    let status = response.status().as_u16();
    match status {
        200 => {
            if let Some(cl) = response.content_length() {
                if cl != expected_bytes {
                    return Err(format!(
                        "Fresh response Content-Length ({cl}) does not match expected size ({expected_bytes})"
                    ));
                }
            }
            Ok(())
        }
        206 => {
            let cr_hdr = response
                .headers()
                .get("Content-Range")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    "Fresh HTTP 206 response missing Content-Range header".to_string()
                })?;
            let parsed = parse_content_range(cr_hdr, 0, expected_bytes)?;
            if parsed.start != 0 || parsed.end != expected_bytes.saturating_sub(1) {
                return Err(format!(
                    "Fresh HTTP 206 Content-Range does not cover entire artifact from byte zero: {cr_hdr}"
                ));
            }
            Ok(())
        }
        other => Err(format!(
            "Fresh restart HTTP request failed with status {other}"
        )),
    }
}

/// Configures the blocking download client with a short connection timeout and
/// a long, finite total request timeout suitable for a 12.1 GB artifact.
pub fn create_http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(DOWNLOAD_REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

/// Evaluates high-level model status according to file presence and verification state.
pub fn derive_model_status(
    final_exists: bool,
    final_len: u64,
    final_sha256_matches: Option<bool>,
    part_exists: bool,
    part_len: u64,
    is_downloading: bool,
    is_verifying: bool,
    expected_bytes: u64,
) -> ModelStatus {
    if is_verifying {
        return ModelStatus::Verifying;
    }
    if is_downloading {
        return ModelStatus::Downloading;
    }
    if final_exists && final_len > 0 {
        if final_len > expected_bytes {
            return ModelStatus::Corrupt;
        }
        match final_sha256_matches {
            Some(true) => ModelStatus::Installed,
            Some(false) => ModelStatus::Corrupt,
            None => ModelStatus::Corrupt, // Cannot be considered installed without verification
        }
    } else if part_exists && part_len > 0 {
        if part_len > expected_bytes {
            ModelStatus::Corrupt
        } else {
            ModelStatus::Partial
        }
    } else {
        ModelStatus::NotInstalled
    }
}

/// Public uncached verification helper for runtime launch-time integrity checking.
pub fn verify_model_integrity_uncached(
    final_path: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(final_path)
        .map_err(|e| format!("Failed to read metadata for {}: {e}", final_path.display()))?;

    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "Model file {} is not a regular file.",
            final_path.display()
        ));
    }

    if metadata.len() != expected_bytes {
        return Ok(false);
    }

    let actual_hash = compute_file_sha256(final_path)?;
    Ok(actual_hash.eq_ignore_ascii_case(expected_sha256))
}

/// Verifies whether the final file matches expected SHA-256 and size, utilizing a cached result
/// when file size and modification timestamp remain unchanged.
/// Uses a mutex to prevent simultaneous duplicate verification passes.
pub fn verify_final_file(
    final_path: &Path,
    expected_sha256: &str,
    expected_bytes: u64,
) -> Result<bool, String> {
    if !final_path.exists() {
        return Ok(false);
    }

    // Acquire verification lock to serialize simultaneous passes
    let _verify_lock = match VERIFY_MUTEX.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let metadata = fs::symlink_metadata(final_path)
        .map_err(|e| format!("Failed to read metadata for {}: {e}", final_path.display()))?;

    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Ok(false);
    }

    let len = metadata.len();
    if len != expected_bytes {
        return Ok(false);
    }
    let mtime = metadata.modified().ok();

    // Cache re-check after acquiring verification lock
    if let Ok(guard) = VERIFIED_CACHE.lock() {
        if let Some(ref cache) = *guard {
            if cache.file_path == final_path
                && cache.file_len == len
                && cache.modified_time == mtime
                && cache.file_len == expected_bytes
            {
                return Ok(cache.is_valid);
            }
        }
    }

    let actual_hash = compute_file_sha256(final_path)?;
    let is_valid = actual_hash.eq_ignore_ascii_case(expected_sha256);

    if let Ok(mut guard) = VERIFIED_CACHE.lock() {
        *guard = Some(VerifiedCacheEntry {
            file_path: final_path.to_path_buf(),
            file_len: len,
            modified_time: mtime,
            is_valid,
        });
    }

    Ok(is_valid)
}

/// Inspects model status for a specific model directory.
pub fn get_model_status_for_dir(model_dir: &Path) -> Result<LocalAiModelStatus, String> {
    validate_model_directory(model_dir)?;
    let is_downloading = ACTIVE_DOWNLOAD.load(Ordering::SeqCst);
    let is_verifying = IS_VERIFYING.load(Ordering::SeqCst);

    let final_path = model_dir.join(FINAL_FILENAME);
    let part_path = model_dir.join(PARTIAL_FILENAME);

    let final_len = match validate_regular_model_file(&final_path, model_dir)? {
        Some(length) => length,
        None => 0,
    };
    let final_exists = final_len > 0;

    let part_len = match validate_regular_model_file(&part_path, model_dir)? {
        Some(length) => length,
        None => 0,
    };
    let part_exists = part_len > 0;

    // Requirement 6: Do not hash an existing final file while status is already Downloading or Verifying.
    let final_sha256_matches = if is_downloading || is_verifying {
        None
    } else if final_exists {
        if final_len != EXPECTED_MODEL_BYTES {
            Some(false)
        } else {
            Some(verify_final_file(
                &final_path,
                EXPECTED_SHA256,
                EXPECTED_MODEL_BYTES,
            )?)
        }
    } else {
        None
    };

    let status = derive_model_status(
        final_exists,
        final_len,
        final_sha256_matches,
        part_exists,
        part_len,
        is_downloading,
        is_verifying,
        EXPECTED_MODEL_BYTES,
    );

    let (downloaded_bytes, total_bytes, model_path, error_message) = match status {
        ModelStatus::Installed => (
            final_len,
            Some(final_len),
            Some(final_path.to_string_lossy().to_string()),
            None,
        ),
        ModelStatus::Corrupt => {
            let (path, len) = if final_exists {
                (Some(final_path.to_string_lossy().to_string()), final_len)
            } else if part_exists {
                (Some(part_path.to_string_lossy().to_string()), part_len)
            } else {
                (None, 0)
            };
            (
                len,
                Some(EXPECTED_MODEL_BYTES),
                path,
                Some("Model file SHA-256 or size check failed.".to_string()),
            )
        }
        ModelStatus::Partial | ModelStatus::Downloading | ModelStatus::Verifying => (
            part_len,
            Some(EXPECTED_MODEL_BYTES),
            Some(part_path.to_string_lossy().to_string()),
            None,
        ),
        ModelStatus::NotInstalled => (0, None, None, None),
    };

    Ok(LocalAiModelStatus {
        name: MODEL_NAME.to_string(),
        status,
        downloaded_bytes,
        total_bytes,
        model_path,
        error_message,
        license: MODEL_LICENSE.to_string(),
        published_size: PUBLISHED_SIZE_DISPLAY.to_string(),
    })
}

/// Removes only the exact final and partial model files in the target directory.
pub fn remove_model_files(model_dir: &Path) -> Result<bool, String> {
    let _control = match DOWNLOAD_CONTROL.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if ACTIVE_DOWNLOAD.load(Ordering::SeqCst) {
        return Err("Cannot remove model while a download is currently active.".to_string());
    }

    if !validate_model_directory(model_dir)? {
        return Ok(false);
    }

    // A status request may be hashing the 12.1 GB file. Wait for that bounded
    // verification operation before attempting a Windows-safe removal.
    let _verify_lock = match VERIFY_MUTEX.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let final_path = model_dir.join(FINAL_FILENAME);
    let part_path = model_dir.join(PARTIAL_FILENAME);

    let mut removed_any = false;

    if fs::symlink_metadata(&final_path).is_ok() {
        validate_regular_model_file(&final_path, model_dir)?;
        fs::remove_file(&final_path)
            .map_err(|e| format!("Failed to remove model file {}: {e}", final_path.display()))?;
        removed_any = true;
    }

    if fs::symlink_metadata(&part_path).is_ok() {
        validate_regular_model_file(&part_path, model_dir)?;
        fs::remove_file(&part_path).map_err(|e| {
            format!(
                "Failed to remove partial model file {}: {e}",
                part_path.display()
            )
        })?;
        removed_any = true;
    }

    clear_verified_cache();

    Ok(removed_any)
}

/// Triggers cooperative cancellation of the active download if one is in progress.
pub fn cancel_download() -> bool {
    let _control = match DOWNLOAD_CONTROL.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if !ACTIVE_DOWNLOAD.load(Ordering::SeqCst) {
        return false;
    }
    CANCEL_REQUESTED.store(true, Ordering::SeqCst);
    true
}

/// Core internal implementation for streaming model downloads.
/// Accepts customizable URL and expected bounds for localhost test fixtures.
pub fn perform_download_stream_core<F>(
    url: &str,
    expected_sha256: &str,
    expected_bytes: u64,
    model_name: &str,
    model_license: &str,
    published_size: &str,
    model_dir: &Path,
    on_progress: F,
) -> Result<LocalAiModelStatus, String>
where
    F: Fn(ModelStatus, u64, u64, f64),
{
    fs::create_dir_all(model_dir).map_err(|e| {
        format!(
            "Failed to create model directory {}: {e}",
            model_dir.display()
        )
    })?;
    validate_model_directory(model_dir)?;

    let final_path = model_dir.join(FINAL_FILENAME);
    let part_path = model_dir.join(PARTIAL_FILENAME);

    // If final file already exists and is verified regular file, return early
    if fs::symlink_metadata(&final_path).is_ok()
        && validate_regular_model_file(&final_path, model_dir)?.is_some()
        && verify_final_file(&final_path, expected_sha256, expected_bytes)?
    {
        return Ok(LocalAiModelStatus {
            name: model_name.to_string(),
            status: ModelStatus::Installed,
            downloaded_bytes: expected_bytes,
            total_bytes: Some(expected_bytes),
            model_path: Some(final_path.to_string_lossy().to_string()),
            error_message: None,
            license: model_license.to_string(),
            published_size: published_size.to_string(),
        });
    }

    let existing_len = match validate_regular_model_file(&part_path, model_dir) {
        Ok(Some(len)) => len,
        Ok(None) => 0,
        Err(e) => return Err(e),
    };

    let client = create_http_client()?;

    let (mut file, mut downloaded_bytes, active_response) =
        if existing_len > 0 && existing_len <= expected_bytes {
            let mut req = client.get(url);
            req = req.header("Range", format!("bytes={existing_len}-"));
            let response = req
                .send()
                .map_err(|e| format!("HTTP Range request to {} failed: {e}", url))?;

            let status_code = response.status().as_u16();
            let content_range = response
                .headers()
                .get("Content-Range")
                .and_then(|v| v.to_str().ok());
            let content_len = response.content_length();

            let decision = resolve_resume_decision(
                status_code,
                content_range,
                content_len,
                existing_len,
                expected_bytes,
            );

            match decision {
                ResumeDecision::AppendValidRange { start_byte, .. } => {
                    validate_regular_model_file(&part_path, model_dir)?;
                    let mut f = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(&part_path)
                        .map_err(|e| format!("Failed to open partial file for appending: {e}"))?;
                    f.seek(SeekFrom::Start(start_byte))
                        .map_err(|e| format!("Failed to seek partial file to {start_byte}: {e}"))?;
                    (f, start_byte, response)
                }
                ResumeDecision::RequiresFreshRestart { reason: _ } => {
                    // Drop the first response immediately!
                    drop(response);

                    // Issue fresh GET without Range header
                    let fresh_resp = client
                        .get(url)
                        .send()
                        .map_err(|e| format!("Fresh restart request to {} failed: {e}", url))?;

                    // Validate replacement response before touching disk
                    validate_fresh_response(&fresh_resp, expected_bytes)?;

                    // Only truncate after replacement response is validated!
                    validate_regular_model_file(&part_path, model_dir)?;
                    let f = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&part_path)
                        .map_err(|e| {
                            format!("Failed to create/truncate partial file for fresh restart: {e}")
                        })?;
                    (f, 0u64, fresh_resp)
                }
                ResumeDecision::FatalError {
                    status_code,
                    message,
                } => {
                    drop(response);
                    return Err(format!(
                        "Download failed with HTTP status {status_code}: {message}"
                    ));
                }
            }
        } else {
            // existing_len is 0 or file exceeded expected size (corrupt) -> Fresh download from 0
            let fresh_resp = client
                .get(url)
                .send()
                .map_err(|e| format!("Initial HTTP request to {} failed: {e}", url))?;

            validate_fresh_response(&fresh_resp, expected_bytes)?;

            validate_regular_model_file(&part_path, model_dir)?;
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&part_path)
                .map_err(|e| format!("Failed to create partial file: {e}"))?;
            (f, 0u64, fresh_resp)
        };

    let mut reader = active_response;
    let mut buffer = [0u8; 64 * 1024]; // 64 KB streaming buffer; never buffers model in RAM
    let mut last_emit = Instant::now();
    let mut last_emit_bytes = downloaded_bytes;

    loop {
        if CANCEL_REQUESTED.load(Ordering::SeqCst) {
            let _ = file.flush();
            let _ = file.sync_all();
            drop(file);
            return Ok(LocalAiModelStatus {
                name: model_name.to_string(),
                status: ModelStatus::Partial,
                downloaded_bytes,
                total_bytes: Some(expected_bytes),
                model_path: Some(part_path.to_string_lossy().to_string()),
                error_message: Some("Download cancelled by user.".to_string()),
                license: model_license.to_string(),
                published_size: published_size.to_string(),
            });
        }

        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = file.flush();
                let _ = file.sync_all();
                return Err(format!("Network stream read error: {e}"));
            }
        };

        // Requirement 2: Abort if streamed bytes would exceed EXPECTED_MODEL_BYTES
        if downloaded_bytes.saturating_add(bytes_read as u64) > expected_bytes {
            let _ = file.flush();
            let _ = file.sync_all();
            return Err(format!(
                "Download stream exceeded expected size of {expected_bytes} bytes. Aborting to prevent unbounded disk usage."
            ));
        }

        if let Err(e) = file.write_all(&buffer[..bytes_read]) {
            return Err(format!("Disk write error: {e}"));
        }

        downloaded_bytes += bytes_read as u64;

        let now = Instant::now();
        if downloaded_bytes.saturating_sub(last_emit_bytes) >= 1024 * 1024
            || now.duration_since(last_emit).as_millis() >= 250
        {
            last_emit = now;
            last_emit_bytes = downloaded_bytes;
            let percent =
                ((downloaded_bytes as f64 / expected_bytes as f64) * 100.0).clamp(0.0, 100.0);
            on_progress(
                ModelStatus::Downloading,
                downloaded_bytes,
                expected_bytes,
                percent,
            );
        }
    }

    file.flush()
        .map_err(|e| format!("Failed flushing partial file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("Failed syncing partial file to disk: {e}"))?;
    drop(file);

    // Requirement 2: Require exactly expected_bytes before SHA-256 verification
    if downloaded_bytes != expected_bytes {
        return Err(format!(
            "Downloaded file size ({downloaded_bytes} bytes) does not match expected size ({expected_bytes} bytes)."
        ));
    }

    on_progress(
        ModelStatus::Downloading,
        downloaded_bytes,
        expected_bytes,
        100.0,
    );

    // Requirement 7: Emit one status=verifying event before SHA-256 verification
    on_progress(
        ModelStatus::Verifying,
        downloaded_bytes,
        expected_bytes,
        100.0,
    );

    IS_VERIFYING.store(true, Ordering::SeqCst);
    let _vguard = VerifyingGuard;

    let actual_hash = compute_file_sha256(&part_path)?;
    if !actual_hash.eq_ignore_ascii_case(expected_sha256) {
        clear_verified_cache();
        return Err(format!(
            "Checksum verification failed for downloaded model. Expected SHA-256: {}, computed: {}. File left as partial/corrupt.",
            expected_sha256, actual_hash
        ));
    }

    // Requirement 3: Corrupt-final replacement on Windows:
    // Only after .part passes size and SHA-256, delete corrupt final if present, then rename.
    if fs::symlink_metadata(&final_path).is_ok() {
        validate_regular_model_file(&final_path, model_dir)?;
        clear_verified_cache();
        fs::remove_file(&final_path).map_err(|e| {
            format!(
                "Failed to remove existing corrupt model file {} before replacement: {e}",
                final_path.display()
            )
        })?;
    }

    validate_regular_model_file(&part_path, model_dir)?;
    fs::rename(&part_path, &final_path).map_err(|e| {
        format!(
            "Failed to rename verified model file {} to {}: {e}",
            part_path.display(),
            final_path.display()
        )
    })?;

    if let Ok(mut guard) = VERIFIED_CACHE.lock() {
        let mtime = final_path.metadata().ok().and_then(|m| m.modified().ok());
        *guard = Some(VerifiedCacheEntry {
            file_path: final_path.clone(),
            file_len: downloaded_bytes,
            modified_time: mtime,
            is_valid: true,
        });
    }

    Ok(LocalAiModelStatus {
        name: model_name.to_string(),
        status: ModelStatus::Installed,
        downloaded_bytes,
        total_bytes: Some(downloaded_bytes),
        model_path: Some(final_path.to_string_lossy().to_string()),
        error_message: None,
        license: model_license.to_string(),
        published_size: published_size.to_string(),
    })
}

/// Production entry point for streaming model download using pinned official constants.
pub fn perform_download_stream<F>(
    model_dir: &Path,
    on_progress: F,
) -> Result<LocalAiModelStatus, String>
where
    F: Fn(ModelStatus, u64, u64, f64),
{
    perform_download_stream_core(
        MODEL_URL,
        EXPECTED_SHA256,
        EXPECTED_MODEL_BYTES,
        MODEL_NAME,
        MODEL_LICENSE,
        PUBLISHED_SIZE_DISPLAY,
        model_dir,
        on_progress,
    )
}

// ---------------------------------------------------------------------------
// Tauri 2 Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn local_ai_model_status(app: AppHandle) -> Result<LocalAiModelStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let model_dir = get_model_dir(&app)?;
        get_model_status_for_dir(&model_dir)
    })
    .await
    .map_err(|e| format!("Model status task join error: {e}"))?
}

#[tauri::command]
pub async fn local_ai_download_model(app: AppHandle) -> Result<LocalAiModelStatus, String> {
    let op_id = {
        let _control = match DOWNLOAD_CONTROL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if ACTIVE_DOWNLOAD.load(Ordering::SeqCst) {
            return Err("A model download is already in progress.".to_string());
        }
        CANCEL_REQUESTED.store(false, Ordering::SeqCst);
        let op_id = CURRENT_DOWNLOAD_ID.fetch_add(1, Ordering::SeqCst) + 1;
        ACTIVE_DOWNLOAD.store(true, Ordering::SeqCst);
        op_id
    };

    let app_for_task = app.clone();
    // Requirement 5: Move DownloadGuard ownership into the blocking worker so dropping
    // the async command future cannot clear ACTIVE_DOWNLOAD while disk/network work continues.
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = DownloadGuard { op_id };
        let model_dir = get_model_dir(&app_for_task)?;
        perform_download_stream(
            &model_dir,
            |status, downloaded_bytes, total_bytes, percent| {
                let _ = app_for_task.emit(
                    "local-ai-download-progress",
                    LocalAiDownloadProgress {
                        status,
                        downloaded_bytes,
                        total_bytes,
                        percent,
                    },
                );
            },
        )
    })
    .await
    .map_err(|e| format!("Model download task join error: {e}"))?
}

#[tauri::command]
pub async fn local_ai_cancel_download(_app: AppHandle) -> Result<bool, String> {
    let was_active = cancel_download();
    Ok(was_active)
}

#[tauri::command]
pub async fn local_ai_remove_model(app: AppHandle) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::local_ai_runtime::GLOBAL_SUPERVISOR.stop()?;
        let model_dir = get_model_dir(&app)?;
        remove_model_files(&model_dir)
    })
    .await
    .map_err(|e| format!("Model removal task join error: {e}"))?
}

// ---------------------------------------------------------------------------
// Offline Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, MutexGuard};

    // The manager deliberately owns process-global download/cancellation/cache
    // state. Serialize these unit tests so Rust's parallel test runner cannot
    // make one test observe another test's active operation or cache entry.
    static TEST_STATE_LOCK: Mutex<()> = Mutex::new(());

    fn lock_test_state() -> MutexGuard<'static, ()> {
        match TEST_STATE_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn test_exact_contained_paths() {
        let _serial = lock_test_state();
        let base = PathBuf::from("C:\\app_local_data\\models\\gpt-oss-20b");

        let valid_final = base.join("gpt-oss-20b-MXFP4.gguf");
        let valid_part = base.join("gpt-oss-20b-MXFP4.gguf.part");
        assert!(is_exact_model_file(&valid_final, &base));
        assert!(is_exact_model_file(&valid_part, &base));

        // Invalid: wrong filename
        let wrong_name = base.join("other_file.txt");
        assert!(!is_exact_model_file(&wrong_name, &base));

        // Invalid: wrong dir
        let wrong_dir = PathBuf::from("C:\\app_local_data\\models\\other-model");
        let wrong_dir_file = wrong_dir.join("gpt-oss-20b-MXFP4.gguf");
        assert!(!is_exact_model_file(&wrong_dir_file, &base));

        // Invalid: directory traversal
        let traversal = base.join("..").join("gpt-oss-20b-MXFP4.gguf");
        assert!(!is_exact_model_file(&traversal, &base));
    }

    #[test]
    fn test_remove_model_files_exactness() {
        let _serial = lock_test_state();
        let temp_dir =
            std::env::temp_dir().join(format!("test_local_ai_remove_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let final_file = temp_dir.join(FINAL_FILENAME);
        let part_file = temp_dir.join(PARTIAL_FILENAME);
        let preserved_file = temp_dir.join("preserved_evidence.log");

        fs::write(&final_file, b"final model bytes").unwrap();
        fs::write(&part_file, b"partial model bytes").unwrap();
        fs::write(&preserved_file, b"important evidence").unwrap();

        let removed = remove_model_files(&temp_dir).unwrap();
        assert!(removed);
        assert!(!final_file.exists());
        assert!(!part_file.exists());
        assert!(
            preserved_file.exists(),
            "Unrelated files must never be removed"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_status_derivation() {
        let _serial = lock_test_state();
        let expected = EXPECTED_MODEL_BYTES;

        // 1. Neither exists -> NotInstalled
        assert_eq!(
            derive_model_status(false, 0, None, false, 0, false, false, expected),
            ModelStatus::NotInstalled
        );

        // 2. Part exists, 0 bytes -> NotInstalled
        assert_eq!(
            derive_model_status(false, 0, None, true, 0, false, false, expected),
            ModelStatus::NotInstalled
        );

        // 3. Part exists, > 0 bytes <= expected -> Partial
        assert_eq!(
            derive_model_status(false, 0, None, true, 1024, false, false, expected),
            ModelStatus::Partial
        );

        // 4. Part exists, > expected -> Corrupt
        assert_eq!(
            derive_model_status(false, 0, None, true, expected + 1, false, false, expected),
            ModelStatus::Corrupt
        );

        // 5. Downloading active -> Downloading
        assert_eq!(
            derive_model_status(false, 0, None, true, 1024, true, false, expected),
            ModelStatus::Downloading
        );

        // 6. Verifying active -> Verifying
        assert_eq!(
            derive_model_status(false, 0, None, true, 1024, true, true, expected),
            ModelStatus::Verifying
        );

        // 7. Final exists, verified matches -> Installed
        assert_eq!(
            derive_model_status(true, expected, Some(true), false, 0, false, false, expected),
            ModelStatus::Installed
        );

        // 8. Final exists, verified mismatch -> Corrupt
        assert_eq!(
            derive_model_status(
                true,
                expected,
                Some(false),
                false,
                0,
                false,
                false,
                expected
            ),
            ModelStatus::Corrupt
        );

        // 9. Final exists, not verified (None) -> Corrupt
        assert_eq!(
            derive_model_status(true, expected, None, false, 0, false, false, expected),
            ModelStatus::Corrupt
        );

        // 10. Final exists, size > expected -> Corrupt
        assert_eq!(
            derive_model_status(
                true,
                expected + 50,
                Some(true),
                false,
                0,
                false,
                false,
                expected
            ),
            ModelStatus::Corrupt
        );
    }

    #[test]
    fn test_checksum_helper() {
        let _serial = lock_test_state();
        let temp_dir =
            std::env::temp_dir().join(format!("test_local_ai_sha_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let test_file = temp_dir.join("test_sha.bin");

        let content = b"LogParser DFIR SHA-256 verification test vector";
        fs::write(&test_file, content).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected = format!("{:x}", hasher.finalize());

        let actual = compute_file_sha256(&test_file).unwrap();
        assert_eq!(actual, expected);

        let non_existent = temp_dir.join("does_not_exist.bin");
        assert!(compute_file_sha256(&non_existent).is_err());

        // Test uncached verification helper
        let uncached_match =
            verify_model_integrity_uncached(&test_file, &expected, content.len() as u64).unwrap();
        assert!(uncached_match);

        let uncached_wrong_len =
            verify_model_integrity_uncached(&test_file, &expected, (content.len() + 1) as u64)
                .unwrap();
        assert!(!uncached_wrong_len);

        let uncached_wrong_hash =
            verify_model_integrity_uncached(&test_file, "deadbeef", content.len() as u64).unwrap();
        assert!(!uncached_wrong_hash);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_content_range_validation() {
        let _serial = lock_test_state();
        let total = 1000u64;

        // Valid Content-Range
        let cr = parse_content_range("bytes 500-999/1000", 500, total).unwrap();
        assert_eq!(
            cr,
            ContentRange {
                start: 500,
                end: 999,
                total: 1000
            }
        );

        // Mismatched expected total
        assert!(parse_content_range("bytes 500-999/2000", 500, total).is_err());

        // Wildcard total rejected
        assert!(parse_content_range("bytes 100-199/*", 100, total).is_err());

        // Mismatched expected start
        assert!(parse_content_range("bytes 0-999/1000", 500, total).is_err());

        // Inverted range (end < start)
        assert!(parse_content_range("bytes 500-400/1000", 500, total).is_err());

        // End >= total
        assert!(parse_content_range("bytes 500-1000/1000", 500, total).is_err());

        // Missing bytes prefix
        assert!(parse_content_range("500-999/1000", 500, total).is_err());

        // Non-numeric values
        assert!(parse_content_range("bytes foo-bar/baz", 500, total).is_err());
    }

    #[test]
    fn test_http_resume_decision_matrix() {
        let _serial = lock_test_state();
        let expected_total = 5000u64;

        // 1. HTTP 206 with valid Content-Range matching existing_len -> AppendValidRange
        let action1 = resolve_resume_decision(
            206,
            Some("bytes 1000-4999/5000"),
            Some(4000),
            1000,
            expected_total,
        );
        assert_eq!(
            action1,
            ResumeDecision::AppendValidRange {
                start_byte: 1000,
                total_bytes: 5000
            }
        );

        // 2. HTTP 206 with mismatched Content-Range start -> RequiresFreshRestart
        let action2 = resolve_resume_decision(
            206,
            Some("bytes 0-4999/5000"),
            Some(5000),
            1000,
            expected_total,
        );
        assert!(matches!(
            action2,
            ResumeDecision::RequiresFreshRestart { .. }
        ));

        // 3. HTTP 206 missing Content-Range -> RequiresFreshRestart
        let action3 = resolve_resume_decision(206, None, Some(4000), 1000, expected_total);
        assert!(matches!(
            action3,
            ResumeDecision::RequiresFreshRestart { .. }
        ));

        // 4. HTTP 200 with existing_len > 0 -> RequiresFreshRestart (drops body, issues fresh GET)
        let action4 = resolve_resume_decision(200, None, Some(5000), 1000, expected_total);
        assert!(matches!(
            action4,
            ResumeDecision::RequiresFreshRestart { .. }
        ));

        // 5. HTTP 416 (Range Not Satisfiable) -> RequiresFreshRestart
        let action6 = resolve_resume_decision(416, None, None, 1000, expected_total);
        assert!(matches!(
            action6,
            ResumeDecision::RequiresFreshRestart { .. }
        ));

        // 6. HTTP 404/500 -> FatalError
        match resolve_resume_decision(404, None, None, 1000, expected_total) {
            ResumeDecision::FatalError { status_code, .. } => assert_eq!(status_code, 404),
            other => panic!("Expected FatalError for 404, got {:?}", other),
        }
    }

    #[test]
    fn test_serde_camel_case() {
        let _serial = lock_test_state();
        let status = LocalAiModelStatus {
            name: MODEL_NAME.to_string(),
            status: ModelStatus::NotInstalled,
            downloaded_bytes: 12345,
            total_bytes: Some(67890),
            model_path: Some("/test/path".to_string()),
            error_message: None,
            license: MODEL_LICENSE.to_string(),
            published_size: PUBLISHED_SIZE_DISPLAY.to_string(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"downloadedBytes\":12345"));
        assert!(json.contains("\"totalBytes\":67890"));
        assert!(json.contains("\"modelPath\":\"/test/path\""));
        assert!(json.contains("\"publishedSize\":\"12.1 GB\""));
        assert!(json.contains("\"status\":\"notInstalled\""));

        // Progress struct must include status in camelCase
        let progress = LocalAiDownloadProgress {
            status: ModelStatus::Downloading,
            downloaded_bytes: 100,
            total_bytes: 200,
            percent: 50.0,
        };
        let progress_json = serde_json::to_string(&progress).unwrap();
        assert!(progress_json.contains("\"status\":\"downloading\""));
        assert!(progress_json.contains("\"downloadedBytes\":100"));
        assert!(progress_json.contains("\"totalBytes\":200"));
        assert!(progress_json.contains("\"percent\":50.0"));

        let verifying_progress = LocalAiDownloadProgress {
            status: ModelStatus::Verifying,
            downloaded_bytes: 200,
            total_bytes: 200,
            percent: 100.0,
        };
        let v_json = serde_json::to_string(&verifying_progress).unwrap();
        assert!(v_json.contains("\"status\":\"verifying\""));
    }

    #[test]
    fn test_non_regular_file_rejection() {
        let _serial = lock_test_state();
        let temp_dir =
            std::env::temp_dir().join(format!("test_local_ai_non_reg_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        // Create a directory where final model file was expected
        let dir_target = temp_dir.join(FINAL_FILENAME);
        fs::create_dir(&dir_target).unwrap();

        let check = validate_regular_model_file(&dir_target, &temp_dir);
        assert!(check.is_err());
        assert!(check.unwrap_err().contains("not a regular file"));

        // Removal must reject non-regular file
        let rem = remove_model_files(&temp_dir);
        assert!(rem.is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    // --- Offline Localhost HTTP Fixture Tests ---

    fn hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    #[test]
    fn test_restart_on_416_and_200_after_range() {
        let _serial = lock_test_state();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload = b"0123456789";
        let payload_len = payload.len() as u64;
        let expected_hash = hash_bytes(payload);

        let req_count = Arc::new(AtomicUsize::new(0));
        let rc = Arc::clone(&req_count);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let count = rc.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(&stream);
                let mut headers = Vec::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                    headers.push(line);
                }

                if count == 0 {
                    // First request has Range: bytes=4-; return 416 Range Not Satisfiable
                    let resp = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes());
                } else {
                    // Fresh request has no Range; return HTTP 200 with full payload
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(payload);
                }
            }
        });

        let temp_dir =
            std::env::temp_dir().join(format!("test_local_ai_restart_416_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let part_file = temp_dir.join(PARTIAL_FILENAME);
        // Pre-create corrupt/out-of-bounds partial file
        fs::write(&part_file, b"OLD_PART").unwrap();

        let url = format!("http://127.0.0.1:{port}/model.gguf");
        let result = perform_download_stream_core(
            &url,
            &expected_hash,
            payload_len,
            MODEL_NAME,
            MODEL_LICENSE,
            PUBLISHED_SIZE_DISPLAY,
            &temp_dir,
            |_status, _down, _tot, _pct| {},
        );

        assert!(
            result.is_ok(),
            "Expected download to succeed on fresh restart after 416: {:?}",
            result
        );
        assert!(
            req_count.load(Ordering::SeqCst) >= 2,
            "Must issue second fresh request"
        );

        let final_file = temp_dir.join(FINAL_FILENAME);
        assert!(final_file.exists());
        assert_eq!(fs::read(&final_file).unwrap(), payload);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_partial_not_truncated_on_invalid_fresh_and_no_error_body_written() {
        let _serial = lock_test_state();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload_len = 10u64;

        let req_count = Arc::new(AtomicUsize::new(0));
        let rc = Arc::clone(&req_count);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let count = rc.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(&stream);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }

                if count == 0 {
                    // First request (Range): returns 200 OK (server ignored Range header)
                    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789";
                    let _ = stream.write_all(resp.as_bytes());
                } else {
                    // Fresh request returns HTTP 500 error body
                    let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\nConnection: close\r\n\r\nFATAL_SERVER_ERROR_XYZ";
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        let temp_dir =
            std::env::temp_dir().join(format!("test_local_ai_no_trunc_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let part_file = temp_dir.join(PARTIAL_FILENAME);
        // Keep the partial smaller than the expected artifact so the code
        // actually sends a Range request before exercising fresh-restart
        // preservation. A larger partial skips the Range branch entirely.
        let original_partial = b"KEEP";
        fs::write(&part_file, original_partial).unwrap();

        let url = format!("http://127.0.0.1:{port}/model.gguf");
        let result = perform_download_stream_core(
            &url,
            "dummy_hash",
            payload_len,
            MODEL_NAME,
            MODEL_LICENSE,
            PUBLISHED_SIZE_DISPLAY,
            &temp_dir,
            |_status, _down, _tot, _pct| {},
        );

        assert!(result.is_err(), "Must fail when fresh restart returns 500");
        assert!(req_count.load(Ordering::SeqCst) >= 2);

        // Verify partial file was NOT truncated and 500 body was NOT written to it!
        let current_part = fs::read(&part_file).unwrap();
        assert_eq!(current_part, original_partial);
        assert!(!String::from_utf8_lossy(&current_part).contains("FATAL_SERVER_ERROR"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_exact_size_mismatch_and_stream_overflow_rejected() {
        let _serial = lock_test_state();
        // Case 1: Header claims 20 bytes when expected is 10
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n01234567890123456789";
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let temp_dir =
            std::env::temp_dir().join(format!("test_local_ai_mismatch_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let url = format!("http://127.0.0.1:{port}/model.gguf");
        let result = perform_download_stream_core(
            &url,
            "hash",
            10, // expects 10 bytes, server header claims 20
            MODEL_NAME,
            MODEL_LICENSE,
            PUBLISHED_SIZE_DISPLAY,
            &temp_dir,
            |_status, _down, _tot, _pct| {},
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match expected size"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_corrupt_final_replacement_preserves_sibling_files() {
        let _serial = lock_test_state();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload = b"NEW_VERIFIED_MODEL_BYTES";
        let payload_len = payload.len() as u64;
        let expected_hash = hash_bytes(payload);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(payload);
            }
        });

        let temp_dir = std::env::temp_dir().join(format!(
            "test_local_ai_corrupt_final_{}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(&temp_dir);

        let final_file = temp_dir.join(FINAL_FILENAME);
        let sibling_file = temp_dir.join("critical_evidence.json");

        fs::write(&final_file, b"OLD_CORRUPT_FINAL_FILE_CONTENT").unwrap();
        fs::write(&sibling_file, b"{\"evidence\": \"untouched\"}").unwrap();

        let url = format!("http://127.0.0.1:{port}/model.gguf");
        let result = perform_download_stream_core(
            &url,
            &expected_hash,
            payload_len,
            MODEL_NAME,
            MODEL_LICENSE,
            PUBLISHED_SIZE_DISPLAY,
            &temp_dir,
            |_status, _down, _tot, _pct| {},
        );

        assert!(
            result.is_ok(),
            "Expected replacement to succeed: {:?}",
            result
        );
        assert_eq!(fs::read(&final_file).unwrap(), payload);
        assert!(sibling_file.exists());
        assert_eq!(
            fs::read(&sibling_file).unwrap(),
            b"{\"evidence\": \"untouched\"}"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_guard_cleanup_on_failure_and_cancel() {
        let _serial = lock_test_state();
        let op_id = 999;
        CURRENT_DOWNLOAD_ID.store(op_id, Ordering::SeqCst);
        ACTIVE_DOWNLOAD.store(true, Ordering::SeqCst);
        CANCEL_REQUESTED.store(true, Ordering::SeqCst);

        {
            let _guard = DownloadGuard { op_id };
            assert!(ACTIVE_DOWNLOAD.load(Ordering::SeqCst));
        }

        // After guard drop, flags must be reset
        assert!(!ACTIVE_DOWNLOAD.load(Ordering::SeqCst));
        assert!(!CANCEL_REQUESTED.load(Ordering::SeqCst));

        // Test that dropping an older guard does not clear newer active download
        let older_guard = DownloadGuard { op_id: 1 };
        CURRENT_DOWNLOAD_ID.store(2, Ordering::SeqCst);
        ACTIVE_DOWNLOAD.store(true, Ordering::SeqCst);
        drop(older_guard);
        assert!(
            ACTIVE_DOWNLOAD.load(Ordering::SeqCst),
            "Older guard must not clear newer download"
        );
        ACTIVE_DOWNLOAD.store(false, Ordering::SeqCst);
    }
}
