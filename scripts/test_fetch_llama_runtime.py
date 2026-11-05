#!/usr/bin/env python3
"""Offline unit tests for scripts/fetch_llama_runtime.py.

Verifies path traversal protections, link rejections, and checksum verification
using synthetic in-memory/temp fixtures without making any network requests.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

import fetch_llama_runtime


class FetchLlamaRuntimeSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="llama_fetch_test_"))
        self.dest_dir = self.temp_dir / "dest"
        self.dest_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_zip_path_traversal_dotdot_rejected(self) -> None:
        zip_path = self.temp_dir / "evil_dotdot.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../escaped.txt", "malicious payload")

        with self.assertRaises(fetch_llama_runtime.ArchiveSecurityError):
            fetch_llama_runtime.safe_extract_zip(zip_path, self.dest_dir)

    def test_zip_path_traversal_absolute_rejected(self) -> None:
        zip_path = self.temp_dir / "evil_abs.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("/etc/passwd", "root:x:0:0:::")

        with self.assertRaises(fetch_llama_runtime.ArchiveSecurityError):
            fetch_llama_runtime.safe_extract_zip(zip_path, self.dest_dir)

    def test_zip_path_traversal_drive_prefix_rejected(self) -> None:
        zip_path = self.temp_dir / "evil_drive.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("C:windows_system.txt", "payload")

        with self.assertRaises(fetch_llama_runtime.ArchiveSecurityError):
            fetch_llama_runtime.safe_extract_zip(zip_path, self.dest_dir)

    def test_tar_path_traversal_dotdot_rejected(self) -> None:
        tar_path = self.temp_dir / "evil_dotdot.tar"
        with tarfile.open(tar_path, "w") as tf:
            info = tarfile.TarInfo(name="../escape.sh")
            data = b"echo hack"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        with self.assertRaises(fetch_llama_runtime.ArchiveSecurityError):
            fetch_llama_runtime.safe_extract_tar(tar_path, self.dest_dir)

    def test_tar_escaping_symlink_rejected(self) -> None:
        tar_path = self.temp_dir / "evil_symlink.tar"
        with tarfile.open(tar_path, "w") as tf:
            info = tarfile.TarInfo(name="symlink_entry")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            tf.addfile(info)

        with self.assertRaises(fetch_llama_runtime.ArchiveSecurityError):
            fetch_llama_runtime.safe_extract_tar(tar_path, self.dest_dir)

    def test_tar_internal_symlink_is_materialized_as_regular_file(self) -> None:
        tar_path = self.temp_dir / "internal_symlink.tar"
        with tarfile.open(tar_path, "w") as tf:
            payload = b"shared library"
            regular = tarfile.TarInfo(name="runtime/libllama.so.1")
            regular.size = len(payload)
            tf.addfile(regular, io.BytesIO(payload))
            link = tarfile.TarInfo(name="runtime/libllama.so")
            link.type = tarfile.SYMTYPE
            link.linkname = "libllama.so.1"
            tf.addfile(link)

        fetch_llama_runtime.safe_extract_tar(tar_path, self.dest_dir)
        materialized = self.dest_dir / "runtime" / "libllama.so"
        self.assertTrue(materialized.is_file())
        self.assertFalse(materialized.is_symlink())
        self.assertEqual(materialized.read_bytes(), b"shared library")

    def test_tar_hardlink_rejected(self) -> None:
        tar_path = self.temp_dir / "evil_hardlink.tar"
        with tarfile.open(tar_path, "w") as tf:
            info = tarfile.TarInfo(name="hardlink_entry")
            info.type = tarfile.LNKTYPE
            info.linkname = "some_other_file"
            tf.addfile(info)

        with self.assertRaises(fetch_llama_runtime.ArchiveSecurityError):
            fetch_llama_runtime.safe_extract_tar(tar_path, self.dest_dir)

    def test_safe_zip_extraction_and_atomic_publish(self) -> None:
        zip_path = self.temp_dir / "valid_runtime.zip"
        binary_name = "llama-server.exe" if os.name == "nt" else "llama-server"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(f"bin/{binary_name}", "mock binary content")
            zf.writestr("bin/ggml.dll", "mock dll")
            zf.writestr("bin/unrelated-tool.exe", "must not ship")

        publish_target = self.temp_dir / "published_runtime"
        fetch_llama_runtime.extract_and_publish(
            zip_path, "zip", binary_name, publish_target
        )

        self.assertTrue((publish_target / binary_name).is_file())
        self.assertTrue((publish_target / "ggml.dll").is_file())
        self.assertTrue((publish_target / "LICENSE.llama.txt").is_file())
        self.assertFalse((publish_target / "unrelated-tool.exe").exists())

    def test_checksum_mismatch_raises(self) -> None:
        corrupted = self.temp_dir / "corrupted.bin"
        corrupted.write_text("corrupted content", encoding="utf-8")
        expected_sha = "0000000000000000000000000000000000000000000000000000000000000000"
        with self.assertRaises(fetch_llama_runtime.ChecksumMismatchError):
            fetch_llama_runtime.verify_archive_checksum(corrupted, expected_sha)

    def test_publish_failure_restores_previous_runtime(self) -> None:
        zip_path = self.temp_dir / "replacement_runtime.zip"
        binary_name = "llama-server.exe" if os.name == "nt" else "llama-server"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(f"bin/{binary_name}", "replacement binary")

        publish_target = self.temp_dir / "existing_runtime"
        publish_target.mkdir()
        (publish_target / binary_name).write_text("known-good binary", encoding="utf-8")

        real_replace = os.replace
        call_count = 0

        def fail_second_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise OSError("synthetic publish failure")
            real_replace(source, target)

        with mock.patch.object(fetch_llama_runtime.os, "replace", side_effect=fail_second_replace):
            with self.assertRaises(OSError):
                fetch_llama_runtime.extract_and_publish(
                    zip_path, "zip", binary_name, publish_target
                )

        self.assertEqual(
            (publish_target / binary_name).read_text(encoding="utf-8"),
            "known-good binary",
        )


if __name__ == "__main__":
    unittest.main()
