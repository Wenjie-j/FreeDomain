#!/usr/bin/env python3
"""Read-only Linux 4.4 UCI network inventory; never generates a replacement config."""
import argparse
import hashlib
import ipaddress
import json
import re
import sys
import tarfile
from pathlib import Path

KNOWN = ("lan", "wan", "wan6", "vpn0", "ipsec_server", "usb")
FIELDS = {"ifname", "device", "type", "proto", "ipaddr", "netmask", "ip6assign"}
KEY = re.compile(r"^network\.([A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_-]+))?=(.*)$")
MAX_UCI_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


def read_evidence_archive(path: Path) -> str:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("evidence archive is too large")
    with tarfile.open(path, mode="r:*") as archive:
        members = {}
        for member in archive.getmembers():
            name = member.name.removeprefix("./")
            if name in ("uci-network.txt", "SHA256SUMS.txt"):
                if name in members or not member.isfile():
                    raise ValueError("invalid evidence archive member")
                members[name] = member
        if set(members) != {"uci-network.txt", "SHA256SUMS.txt"}:
            raise ValueError("required evidence archive member missing")
        uci_member = members["uci-network.txt"]
        sums_member = members["SHA256SUMS.txt"]
        if uci_member.size > MAX_UCI_BYTES or sums_member.size > 1024 * 1024:
            raise ValueError("evidence archive member is too large")
        uci_bytes = archive.extractfile(uci_member).read(MAX_UCI_BYTES + 1)
        sums = archive.extractfile(sums_member).read(1024 * 1024 + 1).decode("ascii")
    expected = None
    for line in sums.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?\.?/?uci-network\.txt", line)
        if match:
            if expected is not None:
                raise ValueError("duplicate UCI checksum")
            expected = match.group(1).lower()
    if expected is None or hashlib.sha256(uci_bytes).hexdigest() != expected:
        raise ValueError("UCI evidence checksum mismatch")
    return uci_bytes.decode("utf-8")


def parse_uci_show(contents: str, expected_management_ip: str | None = None) -> dict:
    sections: dict[str, dict[str, str]] = {}
    for line in contents.splitlines():
        match = KEY.match(line)
        if not match:
            continue
        name, option, value = match.groups()
        if option is None:
            sections.setdefault(name, {})["_kind"] = value.strip("'\"")
        elif option in FIELDS:
            sections.setdefault(name, {})[option] = value.strip("'\"")

    interfaces = {}
    blockers = {"PHYSICAL_ETHERNET_MAPPING_UNVERIFIED", "FIRST_BOOT_RECOVERY_UNVERIFIED"}
    custom_count = 0
    for name, fields in sections.items():
        if fields.get("_kind") != "interface":
            continue
        if name == "loopback":
            continue
        if name in KNOWN:
            label = name
        else:
            custom_count += 1
            label = f"custom_interface_{custom_count}"
        bindings = " ".join(fields.get(k, "") for k in ("ifname", "device"))
        kinds = []
        if re.search(r"\beth[0-9]+\b", bindings):
            kinds.append("LEGACY_ETHERNET")
            blockers.add("PHYSICAL_ETHERNET_MAPPING_UNVERIFIED")
        if re.search(r"\b(?:tun|tap|ipsec|vti)[0-9]*\b|\bip[0-9]+_vti[0-9]+\b", bindings):
            kinds.append("TUNNEL_OR_IPSEC")
            blockers.add("TUNNEL_SERVICE_MIGRATION_UNVERIFIED")
        if re.search(r"\busb[0-9]+\b", bindings):
            kinds.append("USB_NETWORK")
            blockers.add("USB_WAN_MIGRATION_UNVERIFIED")
        if not kinds and bindings:
            kinds.append("OTHER_DEVICE")
            blockers.add("UNKNOWN_INTERFACE_BINDING")
        interfaces[label] = {
            "present_fields": sorted(k for k in fields if k != "_kind"),
            "binding_categories": kinds,
            "protocol_category": fields.get("proto") if fields.get("proto") in
                {"static", "dhcp", "dhcpv6", "none", "pppoe"} else "OTHER_OR_UNSET",
        }
    if "lan" not in interfaces or "wan" not in interfaces:
        blockers.add("LAN_OR_WAN_INTERFACE_MISSING")
    if expected_management_ip is not None:
        expected = ipaddress.ip_address(expected_management_ip)
        actual = sections.get("lan", {}).get("ipaddr")
        try:
            matches = ipaddress.ip_address(actual or "") == expected
        except ValueError:
            matches = False
        if not matches:
            blockers.add("MANAGEMENT_ADDRESS_REQUIRES_EXPLICIT_MIGRATION")
    return {
        "classification": "READ_ONLY_INVENTORY_NOT_FLASH_APPROVAL",
        "decision": "BLOCKED_FIRST_MIGRATION",
        "interfaces": interfaces,
        "blockers": sorted(blockers),
        "next_evidence": [
            "Verify physical port and VLAN mapping on this exact board before converting eth* bindings.",
            "Validate LAN management address and network reachability in a recoverable first boot.",
            "Verify tunnel, USB WAN, firewall4 and proxy interaction before restoring old settings.",
        ],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--uci-show", type=Path,
                        help="Local read-only export of `uci show`, or - for stdin")
    source.add_argument("--evidence-archive", type=Path,
                        help="Private archive from collect_legacy_network_evidence.sh")
    ap.add_argument("--expected-management-ip", help="Compare privately; never printed")
    ap.add_argument("--output", type=Path, help="Sanitized JSON report")
    args = ap.parse_args(argv)
    try:
        if args.evidence_archive:
            payload = read_evidence_archive(args.evidence_archive)
        elif str(args.uci_show) == "-":
            payload = sys.stdin.read(5 * 1024 * 1024 + 1)
        else:
            if args.uci_show.stat().st_size > MAX_UCI_BYTES:
                raise ValueError("input is too large")
            payload = args.uci_show.read_text(encoding="utf-8")
        if len(payload.encode("utf-8")) > MAX_UCI_BYTES:
            raise ValueError("input is too large")
        report = parse_uci_show(payload,
                                args.expected_management_ip)
    except (OSError, UnicodeError, ValueError, tarfile.TarError):
        # Do not include exception text: user supplied paths or values could contain secrets.
        report = {"classification": "READ_ONLY_INVENTORY_NOT_FLASH_APPROVAL",
                  "decision": "BLOCKED_INVALID_INPUT", "blockers": ["INPUT_UNREADABLE_OR_INVALID"]}
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(body, encoding="utf-8")
    print(body, end="")
    return 2


if __name__ == "__main__":
    sys.exit(main())
