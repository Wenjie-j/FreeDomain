#!/usr/bin/env python3
"""Check the V4-built core under QEMU without running a proxy service.

CLI contract: pinned SagerNet/sing-box cmd_version.go and cmd_check.go.
The loader comes from this build's OpenWrt toolchain, not the host libc.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from core_elf import read_core_file
from verify_components import CORE_SOURCE, CORE_TAGS, V4_BASE

VERSION = "1.14.1"
MINIMAL_CONFIG = {
    "log": {"disabled": True},
    "inbounds": [],
    "outbounds": [{"type": "direct", "tag": "direct"}],
    "route": {"final": "direct"},
}
INVALID_CONFIG = {"outbounds": [{"type": "arthur-invalid-outbound"}]}


def interpreter_path(data: bytes) -> str | None:
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    paths = []
    for index in range(header[10]):
        segment = struct.unpack_from("<IIQQQQQQ", data, header[5] + index * header[9])
        if segment[0] == 3:
            raw = data[segment[2]:segment[2] + segment[5]]
            if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                raise ValueError("malformed core interpreter")
            paths.append(raw[:-1].decode("ascii"))
    if len(paths) > 1:
        raise ValueError("multiple core interpreters")
    if paths and paths[0] != "/lib/ld-musl-aarch64.so.1":
        raise ValueError("unexpected core interpreter")
    return paths[0] if paths else None


def run_smoke(binary: Path, trace: dict, sysroot: Path,
              emulator: str = "qemu-aarch64") -> dict:
    data, elf = read_core_file(binary)
    digest = hashlib.sha256(data).hexdigest()
    if (trace.get("binary_sha256") != digest
            or trace.get("base_commit") != V4_BASE
            or trace.get("source_commit") != CORE_SOURCE
            or trace.get("source_version") != VERSION
            or trace.get("target_arch_packages") != "aarch64_cortex-a53"
            or not isinstance(trace.get("build_tags"), list)
            or not CORE_TAGS.issubset(trace["build_tags"])):
        raise ValueError("core does not match the pinned V4 build trace")
    binary = binary.resolve()
    sysroot = sysroot.resolve(strict=True)
    loader_name = interpreter_path(data)
    loader_hash = None
    if loader_name:
        loader = (sysroot / loader_name.lstrip("/")).resolve(strict=True)
        if not loader.is_relative_to(sysroot) or not loader.is_file():
            raise ValueError("core loader escapes the supplied build sysroot")
        loader_hash = hashlib.sha256(loader.read_bytes()).hexdigest()
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("QEMU_", "LD_")) and key != "SING_BOX_CONFIG"}
    command = [emulator, "-L", str(sysroot), "-E", "LD_LIBRARY_PATH=/lib:/usr/lib",
               str(binary)]
    with tempfile.TemporaryDirectory(prefix="arthur-singbox-smoke-") as temp:
        root = Path(temp)
        valid, invalid = root / "minimal.json", root / "invalid.json"
        valid.write_text(json.dumps(MINIMAL_CONFIG))
        invalid.write_text(json.dumps(INVALID_CONFIG))

        def invoke(arguments: list[str]) -> subprocess.CompletedProcess:
            return subprocess.run(command + arguments, cwd=root, env=env,
                                  capture_output=True, text=True, timeout=60)

        version = invoke(["version"])
        if version.returncode or not re.search(
                r"^sing-box version 1\.14\.1$", version.stdout, re.MULTILINE):
            raise ValueError("emulated Sing-box version check failed")
        if not re.search(r"^Environment: \S+ linux/arm64$", version.stdout, re.MULTILINE):
            raise ValueError("emulated Sing-box architecture check failed")
        tag_line = re.search(r"^Tags: (.+)$", version.stdout, re.MULTILINE)
        actual_tags = set(tag_line[1].split(",")) if tag_line else set()
        if not CORE_TAGS.issubset(actual_tags):
            raise ValueError("emulated Sing-box lacks required compiled feature tags")
        if invoke(["check", "-c", str(valid)]).returncode:
            raise ValueError("emulated Sing-box minimal configuration check failed")
        rejected = invoke(["check", "-c", str(invalid)])
        if (rejected.returncode <= 0 or "arthur-invalid-outbound" not in
                rejected.stdout + rejected.stderr):
            raise ValueError("emulated Sing-box did not reject the invalid outbound")
    return {
        "classification": "QEMU_CONFIG_SMOKE_NOT_ARTHUR_RUNTIME_APPROVAL",
        "source_version": VERSION, "binary_sha256": digest,
        "elf_structure": elf, "interpreter": loader_name,
        "build_loader_sha256": loader_hash,
        "actual_build_tags": sorted(actual_tags),
        "version_check": True, "minimal_configuration_check": True,
        "invalid_configuration_rejected": True,
        "proxy_service_started": False, "router_tested": False,
        "status": "PASS_EMULATED_VERSION_TAGS_AND_CONFIG_ONLY",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "trace", "sysroot", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    report = run_smoke(args.binary, json.loads(args.trace.read_text()), args.sysroot)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
