#!/usr/bin/env python3
"""Verify pinned upstream bytes; stage but never execute an OpenClash ARM64 core."""
import argparse
import hashlib
import gzip
import io
import json
from pathlib import Path

SOURCE = "ab405bad5beeeac8b003bb01f60f134f6df54471"
VERSION = "v1.19.31"
ARCHIVE_SHA256 = "9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4"
REPOSITORY = "https://github.com/MetaCubeX/mihomo.git"
ARCHIVE_PATH = "mihomo-linux-arm64-v1.19.31.gz"
DOWNLOAD_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/" + ARCHIVE_PATH
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024


def source_checks(lock: dict) -> dict:
    source = lock.get("openclash_core_source", {})
    expected = {"repository": REPOSITORY, "revision": SOURCE,
                "archive_path": ARCHIVE_PATH, "archive_sha256": ARCHIVE_SHA256,
                "version": VERSION, "download_url": DOWNLOAD_URL}
    if any(source.get(key) != value for key, value in expected.items()):
        raise ValueError("OpenClash core lock differs from reviewed candidate")
    return source


def validate_arm64_elf(data: bytes) -> None:
    if (len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
            or data[18:20] != b"\xb7\x00"
            or int.from_bytes(data[16:18], "little") not in (2, 3)):
        raise ValueError("core must be a little-endian ARM64 ELF executable")


def read_verified_archive(archive: Path, expected_sha256: str) -> tuple[bytes, str]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("missing, symlinked or oversized core archive")
    raw = archive.read_bytes()
    archive_sha = hashlib.sha256(raw).hexdigest()
    if archive_sha != expected_sha256:
        raise ValueError("core archive SHA-256 digest mismatch")
    # A gzip contains no install paths. Do not unpack a tar or invoke a shell.
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
        binary = stream.read(MAX_BINARY + 1)
    if len(binary) > MAX_BINARY:
        raise ValueError("oversized decompressed core executable")
    validate_arm64_elf(binary)
    return binary, archive_sha


def trace_matches(binary: bytes, trace: dict) -> bool:
    try:
        validate_arm64_elf(binary)
    except ValueError:
        return False
    expected = {
        "source_repository": REPOSITORY, "source_commit": SOURCE,
        "source_version": VERSION, "source_archive_path": ARCHIVE_PATH,
        "archive_sha256": ARCHIVE_SHA256, "archive_sha256_verified": True,
        "target_arch": "aarch64", "binary_size": len(binary),
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "executed_during_preparation": False,
    }
    return all(trace.get(key) == value for key, value in expected.items())


def prepare(archive: Path, lock: dict, package_dir: Path) -> dict:
    source = source_checks(lock)
    binary, archive_sha = read_verified_archive(archive, source["archive_sha256"])
    if package_dir.is_symlink() or not (package_dir / "Makefile").is_file():
        raise ValueError("expected existing candidate package recipe")
    files = package_dir / "files"
    if files.is_symlink():
        raise ValueError("refuse symlinked package files directory")
    files.mkdir(exist_ok=True)
    target = files / "clash_meta"
    if target.exists() or target.is_symlink():
        raise ValueError("refuse overwriting an existing staged core")
    target.write_bytes(binary)
    target.chmod(0o755)
    return {
        "classification": "UPSTREAM_PREBUILT_CORE_NOT_RUNTIME_APPROVAL",
        "source_repository": REPOSITORY, "source_commit": SOURCE,
        "source_version": VERSION, "source_archive_path": ARCHIVE_PATH,
        "archive_sha256_verified": True, "archive_sha256": archive_sha,
        "target_arch": "aarch64",
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "binary_size": len(binary), "executed_during_preparation": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--package-dir", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    args = parser.parse_args()
    report = prepare(args.archive, json.loads(args.source_lock.read_text()), args.package_dir)
    args.trace.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
