#!/usr/bin/env python3
"""Verify pinned upstream bytes; stage but never execute an OpenClash ARM64 core."""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path, PurePosixPath

SOURCE = "6b99254c577e4e674887e93f42da89a03b5e9e44"
BLOB = "5c90d325491032c316849c0ed39711a16dfdda4c"
REPOSITORY = "https://github.com/vernesong/OpenClash.git"
ARCHIVE_PATH = "master/meta/clash-linux-arm64.tar.gz"
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024


def source_checks(lock: dict) -> dict:
    source = lock.get("openclash_core_source", {})
    expected = {"repository": REPOSITORY, "revision": SOURCE,
                "archive_path": ARCHIVE_PATH, "git_blob_sha": BLOB}
    if any(source.get(key) != value for key, value in expected.items()):
        raise ValueError("OpenClash core lock differs from reviewed candidate")
    return source


def validate_arm64_elf(data: bytes) -> None:
    if (len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
            or data[18:20] != b"\xb7\x00"
            or int.from_bytes(data[16:18], "little") not in (2, 3)):
        raise ValueError("core must be a little-endian ARM64 ELF executable")


def read_verified_archive(archive: Path, expected_blob: str) -> tuple[bytes, str]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("missing, symlinked or oversized core archive")
    raw = archive.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if blob != expected_blob:
        raise ValueError("core archive Git blob digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        payload = []
        for member in tar:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError("unsafe core archive path")
            if member.isdir() and str(name) == ".":
                continue
            if not member.isfile() or str(name) != "clash":
                raise ValueError("archive must contain only a regular clash executable")
            if not 64 <= member.size <= MAX_BINARY:
                raise ValueError("invalid core executable size")
            payload.append(member)
        if len(payload) != 1:
            raise ValueError("expected exactly one core executable")
        stream = tar.extractfile(payload[0])
        if stream is None:
            raise ValueError("missing core payload")
        binary = stream.read(MAX_BINARY + 1)
    validate_arm64_elf(binary)
    return binary, hashlib.sha256(raw).hexdigest()


def prepare(archive: Path, lock: dict, package_dir: Path) -> dict:
    source = source_checks(lock)
    binary, archive_sha = read_verified_archive(archive, source["git_blob_sha"])
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
        "source_archive_path": ARCHIVE_PATH, "source_blob_sha": BLOB,
        "archive_git_blob_verified": True, "archive_sha256": archive_sha,
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
