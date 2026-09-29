#!/usr/bin/env python3
"""Render an offline firewall4 nftables include for review, never install it.

The candidate must pass `fw4 check` on the target build and live testing of
mark allocation, multi-WAN, NSS, DNS and IPv6 before it can become a service.
"""

import argparse
import ipaddress
import json
import re
from pathlib import Path


BYPASS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
)


def extract_cn4(raw):
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("expected Sing-box geoip rules")
    networks = set()
    for rule in data["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("invalid geoip rule")
        cidrs = rule.get("ip_cidr", [])
        if not isinstance(cidrs, list):
            raise ValueError("invalid ip_cidr list")
        for value in cidrs:
            if not isinstance(value, str):
                raise ValueError("invalid CIDR")
            network = ipaddress.ip_network(value, strict=True)
            if network.version == 4:
                networks.add(network)
    if not 5000 <= len(networks) <= 65536:
        raise ValueError("CN IPv4 CIDR count outside old service safety bounds")
    return sorted(networks, key=lambda net: (int(net.network_address), net.prefixlen))


def render(raw, lan_iface, proxy_endpoint_ipv4):
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", lan_iface):
        raise ValueError("unsafe LAN interface name")
    try:
        endpoint = ipaddress.IPv4Address(proxy_endpoint_ipv4)
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError("explicit proxy endpoint IPv4 is required") from None
    if not endpoint.is_global:
        raise ValueError("proxy endpoint must be a public IPv4 address")
    cidrs = extract_cn4(raw)
    cn = ",\n        ".join(map(str, cidrs))
    bypass = ", ".join(BYPASS)
    return f'''# OFFLINE DRAFT: include inside table inet fw4 only after target checks.
# No private upstream endpoint, node data or credentials are embedded here.
set arthur_cn4 {{
    type ipv4_addr
    flags interval
    auto-merge
    elements = {{
        {cn}
    }}
}}

chain arthur_singbox_udp {{
    type filter hook prerouting priority -151; policy accept;
    iifname != "{lan_iface}" return
    meta nfproto != ipv4 return
    meta l4proto != udp return
    udp dport 53 return
    ip daddr {{ {bypass} }} return
    ip daddr {endpoint} return
    ip daddr @arthur_cn4 return
    tproxy ip to :7895 meta mark set 0x66 accept
}}

chain arthur_singbox_tcp_dns {{
    type nat hook prerouting priority -101; policy accept;
    iifname != "{lan_iface}" return
    meta nfproto != ipv4 return
    udp dport 53 redirect to :53
    tcp dport 53 redirect to :53
    ip daddr {{ {bypass} }} return
    ip daddr {endpoint} return
    ip daddr @arthur_cn4 return
    meta l4proto tcp redirect to :7892
}}

# Matches the existing firmware's explicit LAN IPv6 forward block. Verify
# the desired V4 IPv6 policy before enabling this candidate.
chain arthur_singbox_forward6 {{
    type filter hook forward priority -5; policy accept;
    iifname "{lan_iface}" meta nfproto ipv6 reject
}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geoip-cn", type=Path, required=True)
    parser.add_argument("--lan-iface", required=True)
    parser.add_argument("--proxy-endpoint-ipv4", required=True,
                        help="Private local input; never commit the generated draft")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite an existing nftables include")
    args.output.write_text(render(args.geoip_cn.read_text(), args.lan_iface,
                                  args.proxy_endpoint_ipv4))
    args.output.chmod(0o600)
    print("Offline firewall4 draft written; not installed or syntax checked by nft")


if __name__ == "__main__":
    main()
