"""Bounded read-only FIT subimage hash verification (not signature verification)."""

import hashlib
import struct
import zlib


def _cstring(data, start, limit):
    if not start <= limit <= len(data):
        raise ValueError("FIT string offset outside image")
    end = data.find(b"\0", start, limit)
    if end < 0:
        raise ValueError("FIT string is not terminated")
    try:
        return data[start:end].decode("ascii"), end + 1
    except UnicodeDecodeError:
        raise ValueError("non-ASCII FIT string") from None


def _text(value):
    if not isinstance(value, bytes) or not value or value[-1:] != b"\0" or b"\0" in value[:-1]:
        raise ValueError("invalid FIT string property")
    try:
        return value[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("non-ASCII FIT property") from None


def parse_fit(raw):
    if len(raw) < 40 or len(raw) > 32 * 1024 * 1024:
        raise ValueError("implausible FIT size")
    magic, total, st, strings, _, version, last, _, ns, nt = struct.unpack_from(">10I", raw)
    if magic != 0xd00dfeed or total != len(raw) or version < 16 or last > version:
        raise ValueError("invalid FIT header")
    if not (40 <= st < total and 40 <= strings < total and nt <= total - st
            and ns <= total - strings and st % 4 == 0):
        raise ValueError("FIT structure/string bounds invalid")
    tree = None
    stack = []
    p = st
    nodes = props = 0
    while p + 4 <= st + nt:
        token = struct.unpack_from(">I", raw, p)[0]
        p += 4
        if token == 1:
            name, p = _cstring(raw, p, st + nt)
            p = (p + 3) & ~3
            nodes += 1
            if nodes > 1024 or len(stack) >= 24:
                raise ValueError("FIT tree too large")
            node = {"name": name, "props": {}, "children": {}}
            if stack:
                if name in stack[-1]["children"]:
                    raise ValueError("duplicate FIT node")
                stack[-1]["children"][name] = node
            elif tree is None and name == "":
                tree = node
            else:
                raise ValueError("invalid FIT root")
            stack.append(node)
        elif token == 2:
            if not stack:
                raise ValueError("unbalanced FIT tree")
            stack.pop()
        elif token == 3:
            if not stack or p + 8 > st + nt:
                raise ValueError("invalid FIT property")
            size, offset = struct.unpack_from(">II", raw, p)
            p += 8
            if size > st + nt - p or offset >= ns:
                raise ValueError("FIT property outside bounds")
            key, _ = _cstring(raw, strings + offset, strings + ns)
            props += 1
            if props > 4096 or key in stack[-1]["props"]:
                raise ValueError("duplicate or excessive FIT properties")
            stack[-1]["props"][key] = raw[p:p + size]
            p = (p + size + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            if stack or tree is None:
                raise ValueError("unfinished FIT tree")
            return tree
        else:
            raise ValueError("unknown FIT token")
    raise ValueError("FIT end token missing")


def verify_fit(raw, configuration="config@cp03-c2"):
    tree = parse_fit(raw)
    images = tree["children"].get("images", {}).get("children", {})
    confs = tree["children"].get("configurations", {})
    conf = confs.get("children", {}).get(configuration)
    if conf is None or _text(confs.get("props", {}).get("default")) != configuration:
        raise ValueError("expected FIT configuration is not default")
    algorithms = set()
    for kind, expected_type in (("kernel", "kernel"), ("fdt", "flat_dt")):
        name = _text(conf["props"].get(kind))
        image = images.get(name)
        if image is None or _text(image["props"].get("type")) != expected_type:
            raise ValueError("FIT configuration references wrong subimage")
        data = image["props"].get("data")
        hashes = [child for name, child in image["children"].items()
                  if name.startswith("hash-") or name.startswith("hash@")]
        if not data or not hashes or any(key in image["props"] for key in
                                      ("data-position", "data-offset")):
            raise ValueError("missing or external FIT subimage data/hash")
        strong = False
        for node in hashes:
            algo = _text(node["props"].get("algo"))
            digest = node["props"].get("value")
            expected = {
                "crc32": lambda: struct.pack(">I", zlib.crc32(data)),
                "sha1": lambda: hashlib.sha1(data).digest(),
                "sha256": lambda: hashlib.sha256(data).digest(),
            }.get(algo)
            if expected is None or digest != expected():
                raise ValueError("FIT subimage hash mismatch or unsupported algorithm")
            strong |= algo in ("sha1", "sha256")
            algorithms.add(algo)
        if not strong:
            raise ValueError("FIT subimage lacks a cryptographic digest")
    return sorted(algorithms)
