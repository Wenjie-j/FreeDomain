"""Command-backed firewall4 adapter confined to a marked offline test root.

Requires an injected command runner. Has no CLI and refuses an unmarked root.
Never package this adapter in a firmware image or point it at live paths.
"""

import hashlib
import json
import re
from pathlib import Path

from check_firewall4_mark_space import check


class AdapterError(RuntimeError):
    pass


class SandboxAdapter:
    def __init__(self, root: Path, runner):
        self.root = Path(root).resolve()
        if self.root == Path("/") or not (self.root / ".offline-router-simulation").is_file():
            raise AdapterError("explicit marked offline test root required")
        if runner is None or getattr(runner, "offline_simulation", False) is not True:
            raise AdapterError("explicit offline simulation runner required")
        self.runner = runner
        self.candidate = self.root / "private/candidate.nft"
        self.include = self.root / "etc/nftables.d/90-arthur-singbox.nft"
        self.marker = self.root / "etc/sing-box/arthur/firewall4-owner.json"
        self.created_marker = False
        self.verified_owner = False
        self.saved_include = None

    def _run(self, *args, check_status=True):
        result = self.runner(list(args))
        if check_status and result.returncode != 0:
            raise AdapterError("simulated command failed")
        return result

    def _safe_parent(self, path, create=True):
        try:
            parts = path.parent.relative_to(self.root).parts
        except ValueError:
            raise AdapterError("path outside offline root") from None
        current = self.root
        for part in parts:
            current = current / part
            if current.is_symlink():
                raise AdapterError("symlinked offline path")
            if create:
                current.mkdir(exist_ok=True)

    def preflight(self):
        if (self.include.exists() or self.marker.exists()
                or self.include.is_symlink() or self.marker.is_symlink()):
            return ["EXISTING_INCLUDE_OR_OWNER"]
        rules = self._run("ip", "-4", "rule", "show").stdout
        routes = self._run("ip", "-4", "route", "show", "table", "166").stdout
        fw4 = self._run("fw4", "print").stdout
        mask = self._run("uci", "-q", "get", "mwan3.globals.mmx_mask").stdout.strip()
        return check(rules, routes, fw4, mask)["blockers"]

    def validate_candidate_offline(self):
        if self.candidate.is_symlink() or (self.root / "private").is_symlink():
            raise AdapterError("symlinked private candidate")
        raw = self.candidate.read_bytes()
        if not 100 <= len(raw) <= 2 * 1024 * 1024 or not all(part in raw for part in (
            b"chain arthur_singbox_udp", b"chain arthur_singbox_tcp_dns",
            b"meta l4proto udp tproxy ip to :7895",
            b"meta mark set mark and 0xffffff00 xor 0x66", b"set arthur_cn4",
        )):
            raise AdapterError("invalid offline candidate structure")
        preview = self.root / "private/preview.nft"
        with preview.open("xb") as output:
            output.write(b"table inet fw4 {\n" + raw + b"\n}\n")
        try:
            self._run("nft", "-c", "-f", str(preview))
        finally:
            preview.unlink(missing_ok=True)

    def add_local_route(self):
        self._run("ip", "-4", "route", "add", "local", "0.0.0.0/0",
                  "dev", "lo", "table", "166")

    def add_masked_rule(self):
        self._run("ip", "-4", "rule", "add", "pref", "16666",
                  "fwmark", "0x66/0xff", "table", "166")

    def delete_masked_rule(self):
        self._run("ip", "-4", "rule", "del", "pref", "16666",
                  "fwmark", "0x66/0xff", "table", "166")

    def delete_local_route(self):
        self._run("ip", "-4", "route", "del", "local", "0.0.0.0/0",
                  "dev", "lo", "table", "166")

    def stage_include(self):
        if (self.include.exists() or self.marker.exists()
                or self.include.is_symlink() or self.marker.is_symlink()):
            raise AdapterError("include or owner already exists")
        raw = self.candidate.read_bytes()
        self._safe_parent(self.marker)
        self._safe_parent(self.include)
        self.marker.write_text(json.dumps({"owner": "arthur-singbox-firewall4",
                                           "sha256": hashlib.sha256(raw).hexdigest()}))
        self.created_marker = True
        self.include.write_bytes(raw)
        self.include.chmod(0o600)

    def fw4_check(self):
        self._run("fw4", "check")

    def fw4_reload(self):
        self._run("fw4", "reload")

    def _chains(self, expected):
        for name in ("arthur_singbox_udp", "arthur_singbox_tcp_dns"):
            found = self._run("nft", "list", "chain", "inet", "fw4", name,
                              check_status=False).returncode == 0
            if found != expected:
                raise AdapterError("unexpected proxy chain state")

    def verify_chains(self):
        self._chains(True)

    def verify_chains_absent(self):
        self._chains(False)

    def verify_ownership(self):
        self._safe_parent(self.marker, create=False)
        self._safe_parent(self.include, create=False)
        if self.marker.is_symlink() or self.include.is_symlink():
            raise AdapterError("symlinked owner or include")
        if not self.marker.is_file() or not self.include.is_file():
            raise AdapterError("owner or include missing")
        marker = json.loads(self.marker.read_text())
        if marker.get("owner") != "arthur-singbox-firewall4" or marker.get("sha256") != \
                hashlib.sha256(self.include.read_bytes()).hexdigest():
            raise AdapterError("include ownership mismatch")
        self.verified_owner = True

    def inspect_owned_routing(self):
        if not self.verified_owner:
            raise AdapterError("routing inspection requires verified owner")
        rules = self._run("ip", "-4", "rule", "show").stdout
        routes = self._run("ip", "-4", "route", "show", "table", "166").stdout
        mask = self._run("uci", "-q", "get", "mwan3.globals.mmx_mask").stdout.strip()
        owned = re.compile(r"^\s*16666:\s+from all fwmark 0x66/0xff "
                           r"(?:lookup|table) 166(?:\s|$)")
        others, count = [], 0
        for line in rules.splitlines():
            if owned.match(line):
                count += 1
            else:
                others.append(line)
        if count > 1:
            raise AdapterError("duplicate owned policy rule")
        report = check("\n".join(others), "", "table inet fw4 {}", mask)
        if report["blockers"]:
            raise AdapterError("foreign mark or priority conflict")
        lines = [line.strip() for line in routes.splitlines() if line.strip()]
        if lines and (len(lines) != 1 or not re.fullmatch(
                r"local default dev lo(?: scope host)?", lines[0])):
            raise AdapterError("foreign route in owned table")
        return bool(lines), bool(count)

    def remove_include(self):
        if not (self.created_marker or self.verified_owner):
            if not (self.include.exists() or self.marker.exists()
                    or self.include.is_symlink() or self.marker.is_symlink()):
                return
            raise AdapterError("cannot remove unowned include")
        if self.include.is_symlink() or self.marker.is_symlink():
            raise AdapterError("symlinked owner or include")
        if self.include.is_file():
            self.saved_include = self.include.read_bytes()
            self.include.unlink()
        if self.created_marker:
            self.marker.unlink(missing_ok=True)

    def restore_include(self):
        if (self.saved_include is None or self.include.exists()
                or self.include.is_symlink() or self.marker.is_symlink()):
            raise AdapterError("no safe include restoration")
        self._safe_parent(self.include)
        self.include.write_bytes(self.saved_include)
        self.include.chmod(0o600)
        if self.created_marker and not self.marker.exists():
            self.marker.write_text(json.dumps({"owner": "arthur-singbox-firewall4",
                                               "sha256": hashlib.sha256(self.saved_include).hexdigest()}))

    def release_ownership(self):
        if not self.verified_owner or self.include.exists():
            raise AdapterError("cannot release ownership")
        self.marker.unlink()
