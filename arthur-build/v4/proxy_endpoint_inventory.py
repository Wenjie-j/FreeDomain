#!/usr/bin/env python3
"""Extract proxy IPv4 bypass addresses offline from a private Sing-box config.

DNS results are explicit, private inputs bound to the exact config digest.
This module performs no DNS query, router operation or configuration approval.
"""

import hashlib
import ipaddress
import json
import re
import time
from pathlib import Path

from render_firewall4_draft import normalize_endpoints


SERVER_TYPES = frozenset({
    "socks", "http", "shadowsocks", "vmess", "vless", "trojan",
    "hysteria", "hysteria2", "tuic", "anytls", "shadowtls", "ssh", "naive",
})
GROUP_TYPES = frozenset({"selector", "urltest"})
MAX_BYTES = 2 * 1024 * 1024
MAX_DNS_AGE = 900


def private_bytes(path: Path) -> bytes:
    if (not path.is_file() or any(parent.is_symlink()
                                 for parent in (path, *path.parents))):
        raise ValueError("private input must be a regular non-symlinked file")
    if not 1 <= path.stat().st_size <= MAX_BYTES:
        raise ValueError("private input size outside bounds")
    raw = path.read_bytes()
    if not 1 <= len(raw) <= MAX_BYTES:
        raise ValueError("private input size outside bounds")
    return raw


def strict_json(raw: bytes):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        raise ValueError("private JSON size outside bounds")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key in private JSON")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("non-finite value in private JSON")

    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid private JSON") from None


def domain_name(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("invalid proxy server")
    name = value.removesuffix(".").lower()
    labels = name.split(".")
    if (len(name) > 253 or len(labels) < 2
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in labels)
            or all(label.isdigit() for label in labels)):
        raise ValueError("proxy domain must be an explicit ASCII hostname")
    return name


def config_servers(raw_config: bytes) -> tuple[list[str], set[str], int]:
    config = strict_json(raw_config)
    if not isinstance(config, dict):
        raise ValueError("expected Sing-box configuration object")
    if config.get("endpoints"):
        raise ValueError("Sing-box endpoint transports require a separate reviewed adapter")
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not 1 <= len(outbounds) <= 1024:
        raise ValueError("expected bounded Sing-box outbound list")
    literal_ips, domains = [], set()
    count = 0
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            raise ValueError("invalid Sing-box outbound")
        kind = outbound.get("type")
        if not isinstance(kind, str):
            raise ValueError("invalid Sing-box outbound type")
        if kind == "direct" or kind in GROUP_TYPES:
            if "server" in outbound or "server_port" in outbound:
                raise ValueError("unexpected server on direct or group outbound")
            continue
        if not isinstance(kind, str) or kind not in SERVER_TYPES:
            raise ValueError("unsupported outbound type requires review")
        server = outbound.get("server")
        if not isinstance(server, str) or not server or server != server.strip():
            raise ValueError("proxy outbound server missing or invalid")
        port = outbound.get("server_port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("proxy outbound server_port missing or invalid")
        try:
            address = ipaddress.ip_address(server)
        except ValueError:
            domains.add(domain_name(server))
        else:
            if address.version != 4 or not address.is_global:
                raise ValueError("proxy server requires a public IPv4 or reviewed domain")
            literal_ips.append(str(address))
        count += 1
    if not count:
        raise ValueError("no proxy server outbounds found")
    return literal_ips, domains, count


def collect(raw_config: bytes, raw_snapshot: bytes | None = None,
            now: int | None = None) -> tuple[list[str], dict]:
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError("invalid verification time")
    literal_ips, domains, count = config_servers(raw_config)

    digest = hashlib.sha256(raw_config).hexdigest()
    expires_at = None
    if domains:
        if raw_snapshot is None:
            raise ValueError("fresh private DNS snapshot required for proxy domains")
        snapshot = strict_json(raw_snapshot)
        if (not isinstance(snapshot, dict)
                or set(snapshot) != {"config_sha256", "captured_at", "records"}
                or snapshot["config_sha256"] != digest):
            raise ValueError("DNS snapshot must match the exact private config")
        captured = snapshot["captured_at"]
        if (type(captured) is not int or captured < 0
                or not 0 <= now - captured < MAX_DNS_AGE):
            raise ValueError("DNS snapshot capture time is stale or in the future")
        records = snapshot["records"]
        if not isinstance(records, dict) or set(records) != domains:
            raise ValueError("DNS snapshot must cover exactly all proxy domains")
        for record in records.values():
            if not isinstance(record, dict) or set(record) != {"ipv4", "expires_at"}:
                raise ValueError("invalid proxy DNS record")
            expiry = record["expires_at"]
            if (type(expiry) is not int or not now < expiry <= captured + MAX_DNS_AGE):
                raise ValueError("proxy DNS record expired or exceeds freshness bound")
            addresses = record["ipv4"]
            if not isinstance(addresses, list):
                raise ValueError("proxy DNS IPv4 answers must be a list")
            literal_ips.extend(str(ip) for ip in normalize_endpoints(addresses))
            expires_at = expiry if expires_at is None else min(expires_at, expiry)
    elif raw_snapshot is not None:
        raise ValueError("DNS snapshot supplied without any proxy domains")
    result = [str(ip) for ip in normalize_endpoints(literal_ips)]
    return result, {
        "classification": "PRIVATE_CONFIG_ENDPOINT_INPUT_NOT_DNS_OR_RUNTIME_VERIFICATION",
        "proxy_server_outbound_count": count,
        "proxy_endpoint_ipv4_count": len(result),
        "proxy_domain_count": len(domains),
        "dns_snapshot_valid_until": expires_at,
        "automatic_dns_refresh_implemented": False,
        "target_firewall_activation_approved": False,
    }
