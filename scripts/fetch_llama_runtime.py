#!/usr/bin/env python3
"""Fetch and package pinned llama.cpp release b12080 runtime for offline local AI."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
from pathlib import Path
import posixpath
import shutil
import ssl
import stat
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

LLAMA_RELEASE = "b12080"
CHUNK_SIZE = 8 * 1024 * 1024
USER_AGENT = "log-parser-build/0.3.9"
NETWORK_TIMEOUT_SECONDS = 60
MAX_DOWNLOAD_ATTEMPTS = 4
INITIAL_RETRY_DELAY_SECONDS = 2
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024  # 500 MB upper bound
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB upper bound

RUNTIMES = {
    "windows-x64": {
        "archive": "llama-b12080-bin-win-cpu-x64.zip",
        "sha256": "c0a89dd2edce978ff0a7a5df88e97a735ffab08162e18329c5e964ece6ed160c",
        "binary": "llama-server.exe",
        "type": "zip",
    },
    "linux-x64": {
        "archive": "llama-b12080-bin-ubuntu-x64.tar.gz",
        "sha256": "c7acad3fb4b1154c8cb1cc1d4d5659f7a32e0f224f4baacf1352896588c0858c",
        "binary": "llama-server",
        "type": "tar.gz",
    },
    "macos-arm64": {
        "archive": "llama-b12080-bin-macos-arm64.tar.gz",
        "sha256": "23aa4b646b6ea2ffec03f129da90740a65741aaf6c5a3491e93caebe81d71ac1",
        "binary": "llama-server",
        "type": "tar.gz",
    },
    "macos-x64": {
        "archive": "llama-b12080-bin-macos-x64.tar.gz",
        "sha256": "ff8e236b512399e44c74991db67e9a32cfb137565646ccb77a6d58e9f8e963c2",
        "binary": "llama-server",
        "type": "tar.gz",
    },
}

LLAMA_LICENSE_NOTICE = """MIT License

Copyright (c) 2023-2026 The ggml authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


class ChecksumMismatchError(RuntimeError):
    """Archive did not match its pinned SHA-256 digest."""


class ArchiveSecurityError(RuntimeError):
    """Archive member violates path traversal or file security constraints."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive_checksum(path: Path, expected_sha256: str) -> None:
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise ChecksumMismatchError(
            f"Checksum mismatch: expected {expected_sha256}, got {actual_sha256}"
        )


def validate_member_path(member_path: str, destination: Path) -> Path:
    """Validate that member path is safe and strictly inside destination."""
    # Reject drive prefixes, colons, absolute paths, or double dots
    if os.path.isabs(member_path) or ":" in member_path or member_path.startswith(("\\", "/")):
        raise ArchiveSecurityError(f"Rejected absolute or drive-prefixed path: {member_path}")
    
    parts = Path(member_path).parts
    if ".." in parts:
        raise ArchiveSecurityError(f"Rejected path traversal '..' in member: {member_path}")
    
    target_path = (destination / member_path).resolve()
    dest_resolved = destination.resolve()
    
    try:
        target_path.relative_to(dest_resolved)
    except ValueError:
        raise ArchiveSecurityError(f"Path escapes destination: {member_path}")
    
    return target_path


def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        extracted_bytes = sum(
            member.file_size for member in zf.infolist() if not member.is_dir()
        )
        if extracted_bytes > MAX_EXTRACTED_BYTES:
            raise ArchiveSecurityError(
                f"Archive expands to {extracted_bytes} bytes, exceeding the "
                f"{MAX_EXTRACTED_BYTES}-byte limit"
            )
        for member in zf.infolist():
            # Check for symlinks or special attributes
            # In zip, unix attributes in upper 16 bits of external_attr
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ArchiveSecurityError(f"Rejected symlink entry in zip: {member.filename}")
            
            target = validate_member_path(member.filename, destination)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as source, target.open("wb") as dest:
                    shutil.copyfileobj(source, dest)


def safe_extract_tar(tar_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:*") as tf:
        members = tf.getmembers()
        extracted_bytes = sum(member.size for member in members if member.isreg())
        if extracted_bytes > MAX_EXTRACTED_BYTES:
            raise ArchiveSecurityError(
                f"Archive expands to {extracted_bytes} bytes, exceeding the "
                f"{MAX_EXTRACTED_BYTES}-byte limit"
            )
        link_members: list[tarfile.TarInfo] = []
        for member in members:
            if member.issym() or member.islnk():
                validate_member_path(member.name, destination)
                link_members.append(member)
                continue
            if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                raise ArchiveSecurityError(f"Rejected device/fifo entry in tar: {member.name}")
            
            target = validate_member_path(member.name, destination)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                fileobj = tf.extractfile(member)
                if fileobj is None:
                    raise ArchiveSecurityError(f"Could not read regular file member: {member.name}")
                with fileobj, target.open("wb") as dest:
                    shutil.copyfileobj(fileobj, dest)
            else:
                raise ArchiveSecurityError(f"Unsupported tar member type: {member.name}")

        if len(link_members) > 1024:
            raise ArchiveSecurityError("Archive contains too many link entries")

        members_by_name = {posixpath.normpath(member.name): member for member in members}
        materialized_bytes = extracted_bytes
        for member in link_members:
            source_member = resolve_tar_link(member, members_by_name)
            materialized_bytes += source_member.size
            if materialized_bytes > MAX_EXTRACTED_BYTES:
                raise ArchiveSecurityError(
                    "Materialized tar links exceed the extracted-size limit"
                )
            source = validate_member_path(source_member.name, destination)
            target = validate_member_path(member.name, destination)
            if not source.is_file() or source.is_symlink():
                raise ArchiveSecurityError(
                    f"Tar link target is not an extracted regular file: {member.name}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def resolve_tar_link(
    member: tarfile.TarInfo,
    members_by_name: dict[str, tarfile.TarInfo],
) -> tarfile.TarInfo:
    """Resolve an internal tar link to a regular member without creating links."""
    current = member
    visited: set[str] = set()
    for _ in range(16):
        normalized_current = posixpath.normpath(current.name)
        if normalized_current in visited:
            raise ArchiveSecurityError(f"Tar link cycle detected at: {current.name}")
        visited.add(normalized_current)

        if current.isreg():
            return current
        if not (current.issym() or current.islnk()):
            raise ArchiveSecurityError(
                f"Tar link does not resolve to a regular file: {member.name}"
            )

        link_name = current.linkname.replace("\\", "/")
        if not link_name or posixpath.isabs(link_name) or ":" in link_name:
            raise ArchiveSecurityError(f"Rejected unsafe tar link: {current.name}")
        if current.issym():
            candidate = posixpath.normpath(
                posixpath.join(posixpath.dirname(current.name), link_name)
            )
        else:
            candidate = posixpath.normpath(link_name)
        if candidate == ".." or candidate.startswith("../"):
            raise ArchiveSecurityError(f"Tar link escapes archive root: {current.name}")

        target_member = members_by_name.get(candidate)
        if target_member is None:
            raise ArchiveSecurityError(
                f"Tar link target is absent from archive: {current.name} -> {candidate}"
            )
        current = target_member

    raise ArchiveSecurityError(f"Tar link chain is too deep: {member.name}")


def download_archive(url: str, expected_sha256: str, download_path: Path) -> None:
    retryable_errors = (
        urllib.error.URLError,
        TimeoutError,
        ConnectionError,
        http.client.HTTPException,
        ssl.SSLError,
        ChecksumMismatchError,
    )
    temp_download = download_path.with_name(download_path.name + ".part")

    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        temp_download.unlink(missing_ok=True)
        print(f"Downloading {url} (attempt {attempt}/{MAX_DOWNLOAD_ATTEMPTS})...")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT_SECONDS) as response, \
                 temp_download.open("wb") as out:
                digest = hashlib.sha256()
                bytes_downloaded = 0
                while chunk := response.read(CHUNK_SIZE):
                    bytes_downloaded += len(chunk)
                    if bytes_downloaded > MAX_ARCHIVE_BYTES:
                        raise RuntimeError(
                            f"Archive exceeded maximum bounded size of {MAX_ARCHIVE_BYTES} bytes"
                        )
                    out.write(chunk)
                    digest.update(chunk)
            
            actual_sha256 = digest.hexdigest()
            if actual_sha256 != expected_sha256:
                raise ChecksumMismatchError(
                    f"Checksum mismatch: expected {expected_sha256}, got {actual_sha256}"
                )
            
            os.replace(temp_download, download_path)
            print(f"Verified archive SHA-256: {actual_sha256}")
            return
        except retryable_errors as error:
            temp_download.unlink(missing_ok=True)
            if attempt == MAX_DOWNLOAD_ATTEMPTS:
                raise RuntimeError(
                    f"Failed to download archive after {MAX_DOWNLOAD_ATTEMPTS} attempts: {error}"
                ) from error
            delay = INITIAL_RETRY_DELAY_SECONDS * (2 ** (attempt - 1))
            print(f"Attempt {attempt} failed: {error}; retrying in {delay}s...", file=sys.stderr)
            time.sleep(delay)
        finally:
            temp_download.unlink(missing_ok=True)


def extract_and_publish(archive_path: Path, archive_type: str, expected_binary: str, destination: Path) -> None:
    """Extract archive into a staging dir and atomically publish to destination."""
    staging_parent = destination.parent
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix="llama_runtime_staging_", dir=staging_parent))
    
    final_staging: Path | None = None
    backup: Path | None = None
    try:
        if archive_type == "zip":
            safe_extract_zip(archive_path, staging_dir)
        elif archive_type.startswith("tar"):
            safe_extract_tar(archive_path, staging_dir)
        else:
            raise ValueError(f"Unknown archive type: {archive_type}")
        
        # In llama.cpp binary archives, binaries might be directly in root or in a subfolder.
        # Find the expected executable in staging_dir
        binary_candidates = list(staging_dir.glob(f"**/{expected_binary}"))
        if not binary_candidates:
            raise RuntimeError(f"Expected binary '{expected_binary}' not found in extracted archive")
        
        binary_file = binary_candidates[0]
        if not binary_file.is_file() or binary_file.is_symlink():
            raise RuntimeError(f"Expected binary '{binary_file}' is not a regular file")
        
        # Determine runtime source directory (where binary and shared libraries are)
        runtime_src_dir = binary_file.parent
        
        # Verify and make executable on Unix
        if os.name != "nt":
            current_mode = binary_file.stat().st_mode
            binary_file.chmod(current_mode | 0o755)
            # Make sure all other executables or shared libs are readable/executable
            for file in runtime_src_dir.glob("*"):
                if file.is_file() and not file.is_symlink():
                    file.chmod(file.stat().st_mode | 0o755)
        
        # Write upstream license notice into the runtime dir
        license_file = runtime_src_dir / "LICENSE.llama.txt"
        license_file.write_text(LLAMA_LICENSE_NOTICE, encoding="utf-8")
        
        # Atomically replace destination with runtime_src_dir contents
        final_staging = Path(tempfile.mkdtemp(prefix="llama_runtime_final_", dir=staging_parent))
        for item in runtime_src_dir.iterdir():
            if not is_runtime_component(item, expected_binary):
                continue
            target = final_staging / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)
        
        # Ensure executable exists in final_staging
        final_binary = final_staging / expected_binary
        if not final_binary.is_file() or final_binary.is_symlink():
            raise RuntimeError(f"Final binary '{final_binary}' validation failed")
        
        # Publish with rollback: preserve the previous known-good runtime until
        # the fully validated staging directory has been moved into place.
        if destination.exists():
            backup = Path(tempfile.mkdtemp(prefix="llama_runtime_backup_", dir=staging_parent))
            backup.rmdir()
            os.replace(destination, backup)

        try:
            os.replace(final_staging, destination)
            final_staging = None
        except BaseException:
            if backup is not None and backup.exists() and not destination.exists():
                os.replace(backup, destination)
                backup = None
            raise

        if backup is not None and backup.exists():
            if backup.is_dir():
                shutil.rmtree(backup)
            else:
                backup.unlink()
            backup = None
        print(f"Successfully published llama runtime to: {destination}")
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)
        if final_staging is not None:
            shutil.rmtree(final_staging, ignore_errors=True)
        if backup is not None and backup.exists() and not destination.exists():
            os.replace(backup, destination)


def is_runtime_component(path: Path, expected_binary: str) -> bool:
    """Keep only llama-server, its shared libraries, and required notices."""
    if not path.is_file() or path.is_symlink():
        return False
    name = path.name
    lower_name = name.lower()
    return (
        name == expected_binary
        or lower_name.startswith("license")
        or lower_name.endswith(".dll")
        or ".so" in lower_name
        or lower_name.endswith(".dylib")
    )


def fetch_runtime(platform_id: str, destination: Path, cache_dir: Path | None = None) -> None:
    if platform_id not in RUNTIMES:
        raise ValueError(f"Unknown platform '{platform_id}'. Supported: {list(RUNTIMES.keys())}")
    
    config = RUNTIMES[platform_id]
    archive_name = config["archive"]
    expected_sha256 = config["sha256"]
    expected_binary = config["binary"]
    archive_type = config["type"]
    url = f"https://github.com/ggml-org/llama.cpp/releases/download/{LLAMA_RELEASE}/{archive_name}"

    if cache_dir is None:
        cache_dir = destination.parent / "downloads"
    cache_dir.mkdir(parents=True, exist_ok=True)
    archive_path = cache_dir / archive_name

    # Check if cached archive is valid
    if archive_path.is_file():
        try:
            verify_archive_checksum(archive_path, expected_sha256)
            print(f"Using cached archive: {archive_path}")
        except ChecksumMismatchError:
            archive_path.unlink(missing_ok=True)
            download_archive(url, expected_sha256, archive_path)
    else:
        download_archive(url, expected_sha256, archive_path)
    
    extract_and_publish(archive_path, archive_type, expected_binary, destination)


def parse_args() -> argparse.Namespace:
    default_dest = (
        Path(__file__).resolve().parents[1]
        / "src-tauri"
        / "resources"
        / "llama-cpp-runtime"
    )
    parser = argparse.ArgumentParser(
        description="Fetch and package pinned llama.cpp release b12080 runtime."
    )
    parser.add_argument(
        "--platform",
        required=True,
        choices=list(RUNTIMES.keys()),
        help="Target platform identifier (never guessed)",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=default_dest,
        help=f"Destination directory for extracted runtime (default: {default_dest})",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="Directory to cache downloaded archives",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    fetch_runtime(args.platform, args.destination.resolve(), args.cache_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
