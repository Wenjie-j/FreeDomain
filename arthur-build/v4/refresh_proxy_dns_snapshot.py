#!/usr/bin/env python3
"""Refresh a private DNS snapshot offline using bounded dig queries.

No firewall or router service is touched. A failed refresh leaves the prior
snapshot file intact; retaining an expired file never extends its validity.
Requires dig on the execution host; this is not a target service integration.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from proxy_endpoint_inventory import (
    MAX_DNS_AGE, collect, config_servers, domain_name, private_bytes, strict_json,
)
from render_firewall4_draft import normalize_endpoints

MAX_DOMAINS = 128
MAX_ANSWER_BYTES = 65536
QUERY_BUDGET = 45


def parse_answer(text: str, domain: str) -> tuple[list[str], int]:
    if not isinstance(text, str) or not 1 <= len(text.encode()) <= MAX_ANSWER_BYTES:
        raise ValueError("DNS answer size outside bounds")
    domain = domain_name(domain)
    headers, questions, flags, answer_counts, records = [], [], [], [], {}
    record_count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(";; ->>HEADER<<-"):
            match = re.fullmatch(r";; ->>HEADER<<- opcode: QUERY, status: ([A-Z]+), id: [0-9]+", line)
            if match is None:
                raise ValueError("invalid DNS response header")
            headers.append(match[1])
        elif line.startswith(";; flags:"):
            match = re.fullmatch(r";; flags: ([a-z ]+); QUERY: 1, ANSWER: ([0-9]+), AUTHORITY: [0-9]+, ADDITIONAL: [0-9]+", line)
            if match is None:
                raise ValueError("invalid DNS response counts")
            flags.append(set(match[1].split()))
            answer_counts.append(int(match[2]))
        elif line.startswith(";;"):
            continue
        elif line.startswith(";"):
            match = re.fullmatch(r";([^\s]+)\s+IN\s+A", line)
            if match is None:
                raise ValueError("invalid DNS response question")
            questions.append(domain_name(match[1]))
        else:
            fields = line.split()
            if (len(fields) != 5 or fields[2] != "IN"
                    or fields[3] not in {"A", "CNAME"}
                    or not fields[1].isdigit()):
                raise ValueError("unsupported or malformed DNS answer record")
            ttl = int(fields[1])
            if not 1 <= ttl <= 2147483647:
                raise ValueError("DNS answer TTL is unusable")
            owner = domain_name(fields[0])
            kind = fields[3]
            value = fields[4]
            if kind == "CNAME":
                value = domain_name(value)
            else:
                value = str(normalize_endpoints([value])[0])
            records.setdefault(owner, []).append((kind, value, ttl))
            record_count += 1
    if (headers != ["NOERROR"] or questions != [domain]
            or len(flags) != 1 or "qr" not in flags[0] or "tc" in flags[0]
            or answer_counts != [record_count] or not record_count):
        raise ValueError("DNS response failed or was incomplete")
    owner, seen, minimum_ttl = domain, set(), MAX_DNS_AGE
    while True:
        if owner in seen or len(seen) >= 16:
            raise ValueError("DNS CNAME chain loops or exceeds bounds")
        seen.add(owner)
        answers = records.get(owner)
        if not answers:
            raise ValueError("DNS answer has no complete address chain")
        kinds = {kind for kind, _, _ in answers}
        minimum_ttl = min(minimum_ttl, *(ttl for _, _, ttl in answers))
        if kinds == {"A"}:
            if set(records) != seen:
                raise ValueError("DNS answer includes unrelated records")
            return [str(ip) for ip in normalize_endpoints(
                [value for _, value, _ in answers])], minimum_ttl
        if kinds != {"CNAME"} or len(answers) != 1:
            raise ValueError("DNS answer has ambiguous CNAME records")
        owner = answers[0][1]


def _clock(clock) -> int:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (float, int)) or value < 0:
        raise ValueError("invalid DNS capture time")
    try:
        return int(value)
    except (ValueError, OverflowError):
        raise ValueError("invalid DNS capture time") from None


def build_snapshot(raw_config: bytes, resolver: str, *, runner=None,
                   clock=time.time, dig="dig") -> tuple[bytes, dict]:
    resolver = str(normalize_endpoints([resolver])[0])
    _, domains, _ = config_servers(raw_config)
    if not domains or len(domains) > MAX_DOMAINS:
        raise ValueError("DNS refresh requires between 1 and 128 proxy domains")
    runner = subprocess.run if runner is None else runner
    captured = _clock(clock)
    records = {}
    env = dict(os.environ, LC_ALL="C")
    for domain in sorted(domains):
        queried = _clock(clock)
        elapsed = queried - captured
        if not 0 <= elapsed < QUERY_BUDGET:
            raise ValueError("DNS refresh budget exceeded or clock moved backward")
        command = [str(dig), "-r", "-4", "@" + resolver, "-q", domain + ".", "-t", "A",
                   "+recurse", "+nosearch", "+noall", "+comments", "+question",
                   "+answer", "+ttlid", "+nottlunits", "+noqr", "+noedns", "+tries=1", "+time=2"]
        try:
            result = runner(command, check=True, capture_output=True, text=True,
                            timeout=min(5, QUERY_BUDGET - elapsed), env=env)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise ValueError("proxy DNS query failed") from None
        addresses, ttl = parse_answer(result.stdout, domain)
        records[domain] = {"ipv4": addresses,
                           "expires_at": min(queried + ttl, captured + MAX_DNS_AGE)}
    finished = _clock(clock)
    if not 0 <= finished - captured < QUERY_BUDGET:
        raise ValueError("DNS refresh budget exceeded or clock moved backward")
    snapshot = {
        "config_sha256": hashlib.sha256(raw_config).hexdigest(),
        "captured_at": captured,
        "records": records,
    }
    raw_snapshot = (json.dumps(snapshot, sort_keys=True, indent=2) + "\n").encode()
    _, report = collect(raw_config, raw_snapshot, now=finished)
    report = dict(report, classification="PRIVATE_OFFLINE_DNS_REFRESH_NOT_TARGET_INTEGRATION",
                  query_count=len(records), offline_dns_query_implemented=True,
                  scheduled_refresh_implemented=False,
                  target_dns_consistency_verified=False)
    return raw_snapshot, report


def _safe_output(output: Path):
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError("DNS snapshot output has a symlinked path")
    if output.exists():
        if not output.is_file():
            raise ValueError("DNS snapshot output must be a regular file")
        previous = strict_json(private_bytes(output))
        if (not isinstance(previous, dict)
                or set(previous) != {"config_sha256", "captured_at", "records"}
                or not isinstance(previous["config_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", previous["config_sha256"])
                or type(previous["captured_at"]) is not int
                or not isinstance(previous["records"], dict)):
            raise ValueError("refusing to replace a file that is not a DNS snapshot")


def refresh(config: Path, resolver: str, output: Path, *, runner=None,
            clock=time.time, dig="dig") -> dict:
    raw_config = private_bytes(config)
    _safe_output(output)
    if output.absolute() == config.absolute():
        raise ValueError("DNS snapshot must not replace private configuration")
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.parent / ("." + output.name + ".refresh-lock")
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError("DNS snapshot refresh already locked") from None
    temp_path = None
    try:
        # Capture prior identity under the lock, then recheck before commit.
        _safe_output(output)
        prior = output.read_bytes() if output.exists() else None
        raw_snapshot, report = build_snapshot(raw_config, resolver, runner=runner,
                                             clock=clock, dig=dig)
        if private_bytes(config) != raw_config:
            raise ValueError("private config changed during DNS refresh")
        with tempfile.NamedTemporaryFile("wb", dir=output.parent,
                                         prefix=".dns-snapshot-", delete=False) as target:
            temp_path = Path(target.name)
            target.write(raw_snapshot)
            target.flush()
            os.fsync(target.fileno())
        temp_path.chmod(0o600)
        _safe_output(output)
        current = output.read_bytes() if output.exists() else None
        if current != prior:
            raise ValueError("DNS snapshot changed during refresh")
        collect(raw_config, raw_snapshot, now=_clock(clock))
        if private_bytes(config) != raw_config:
            raise ValueError("private config changed before DNS snapshot commit")
        os.replace(temp_path, output)
        report["snapshot_replaced_atomically"] = True
        return report
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--singbox-config", type=Path, required=True)
    parser.add_argument("--resolver-ipv4", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(refresh(args.singbox_config, args.resolver_ipv4, args.output), indent=2))


if __name__ == "__main__":
    main()
