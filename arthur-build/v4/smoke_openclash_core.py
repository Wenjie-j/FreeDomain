#!/usr/bin/env python3
"""Run stable core version/config checks in cloud QEMU, never a proxy service."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from prepare_openclash_core import VERSION, trace_matches

MINIMAL_CONFIG = """port: 0
mixed-port: 0
socks-port: 0
redir-port: 0
tproxy-port: 0
mode: direct
log-level: silent
ipv6: false
external-controller: ''
dns:
  enable: false
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
"""


def run_smoke(binary: Path, trace: dict, emulator: str = "qemu-aarch64") -> dict:
    binary = binary.resolve()
    if not binary.is_file() or not trace_matches(binary.read_bytes(), trace):
        raise ValueError("refuse to run core without matching stable preparation trace")
    with tempfile.TemporaryDirectory(prefix="arthur-core-smoke-") as temp:
        root = Path(temp)
        config = root / "minimal.yaml"
        config.write_text(MINIMAL_CONFIG, encoding="utf-8")
        version = subprocess.run([emulator, str(binary), "-v"], cwd=root,
                                 capture_output=True, text=True, timeout=45)
        # Require the complete version token; v1.19.310 is not v1.19.31.
        if version.returncode or VERSION not in version.stdout.split():
            raise ValueError("emulated core version check failed")
        checked = subprocess.run([emulator, str(binary), "-t", "-d", str(root),
                                  "-f", str(config)], cwd=root,
                                 capture_output=True, text=True, timeout=45)
        if checked.returncode:
            raise ValueError("emulated minimal configuration check failed: "
                             + (checked.stderr + checked.stdout)[-1000:])
    return {
        "classification": "QEMU_CONFIG_SMOKE_NOT_ARTHUR_RUNTIME_APPROVAL",
        "source_version": VERSION, "binary_sha256": trace["binary_sha256"],
        "version_check": True, "minimal_configuration_check": True,
        "proxy_service_started": False, "router_tested": False,
        "status": "PASS_EMULATED_VERSION_AND_CONFIG_ONLY",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = run_smoke(args.binary, json.loads(args.trace.read_text()))
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
