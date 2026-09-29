#!/usr/bin/env python3
"""Make a private firewall4 draft from the exact Sing-box CN .srs bytes.

Requires a runnable Sing-box 1.14.1 binary for the execution host. No router
service or firewall is changed. Do not install the resulting draft.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from render_firewall4_draft import extract_cn4, render


def prepare(binary: Path, srs: Path, lan_iface: str,
            proxy_endpoint_ipv4: str, output: Path):
    if output.exists():
        raise ValueError("refusing to replace existing candidate")
    raw_srs = srs.read_bytes()
    if not 100 <= len(raw_srs) <= 16 * 1024 * 1024:
        raise ValueError("unexpected CN rule-set size")
    with tempfile.TemporaryDirectory(prefix="arthur-cn-") as directory:
        decoded = Path(directory) / "cn.json"
        try:
            subprocess.run(
                [str(binary), "rule-set", "decompile", "--output", str(decoded), str(srs)],
                check=True, capture_output=True, timeout=45,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise ValueError("Sing-box rule-set decompile failed") from None
        if not decoded.is_file() or decoded.stat().st_size > 24 * 1024 * 1024:
            raise ValueError("missing or oversized decompiled CN rule-set")
        raw_json = decoded.read_text()
        count = len(extract_cn4(raw_json))
        draft = render(raw_json, lan_iface, proxy_endpoint_ipv4)

    output.parent.mkdir(parents=True, exist_ok=True)
    # Link a complete temporary file into place without replacing older output.
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=output.parent,
                                         prefix=".arthur-cn-", delete=False) as target:
            tmp_path = Path(target.name)
            target.write(draft)
        tmp_path.chmod(0o600)
        os.link(tmp_path, output)
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
    return {
        "source_srs_sha256": hashlib.sha256(raw_srs).hexdigest(),
        "candidate_nft_sha256": hashlib.sha256(draft.encode()).hexdigest(),
        "cn_ipv4_cidr_count": count,
        "status": "OFFLINE_DRAFT_REQUIRES_FW4_AND_HARDWARE_TEST",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--geoip-cn-srs", type=Path, required=True)
    parser.add_argument("--lan-iface", required=True)
    parser.add_argument("--proxy-endpoint-ipv4", required=True,
                        help="Private local input; never commit the generated draft")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.sing_box, args.geoip_cn_srs,
                             args.lan_iface, args.proxy_endpoint_ipv4,
                             args.output), indent=2))


if __name__ == "__main__":
    main()
