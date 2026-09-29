import hashlib
import struct
import unittest

from fit_integrity import verify_fit


def fixture():
    """Tiny valid FIT with two independently hashed inline subimages."""
    strings = bytearray()
    offsets = {}
    block = bytearray()

    def token(value):
        block.extend(struct.pack(">I", value))

    def aligned(value):
        block.extend(value)
        block.extend(b"\0" * (-len(block) % 4))

    def begin(name):
        token(1)
        aligned(name.encode() + b"\0")

    def end():
        token(2)

    def prop(name, value):
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(name.encode() + b"\0")
        token(3)
        block.extend(struct.pack(">II", len(value), offsets[name]))
        aligned(value)

    begin("")
    begin("images")
    for name, kind, data in (("kernel-1", "kernel", b"KERNEL-CONTENTS"),
                             ("fdt-1", "flat_dt", b"FDT-CONTENTS")):
        begin(name)
        prop("type", kind.encode() + b"\0")
        prop("data", data)
        begin("hash-1")
        prop("algo", b"sha1\0")
        prop("value", hashlib.sha1(data).digest())
        end()
        end()
    end()
    begin("configurations")
    prop("default", b"config@cp03-c2\0")
    begin("config@cp03-c2")
    prop("kernel", b"kernel-1\0")
    prop("fdt", b"fdt-1\0")
    end()
    end()
    end()
    token(9)
    st = 40
    ss = st + len(block)
    total = ss + len(strings)
    header = struct.pack(">10I", 0xd00dfeed, total, st, ss, 0,
                         17, 16, 0, len(strings), len(block))
    return header + block + strings


class FitIntegrityTest(unittest.TestCase):
    def test_both_configured_subimages_have_matching_digests(self):
        raw = fixture()
        self.assertEqual(verify_fit(raw), ["sha1"])
        damaged = raw.replace(b"KERNEL-CONTENTS", b"KERNEL-CONTENTX")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_fit(damaged)
        damaged = raw.replace(b"FDT-CONTENTS", b"FDT-CONTENTX")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_fit(damaged)

    def test_wrong_default_or_malformed_tree_is_rejected(self):
        raw = fixture()
        with self.assertRaises(ValueError):
            verify_fit(raw.replace(b"config@cp03-c2\0", b"config@cp03-c3\0", 1))
        with self.assertRaises(ValueError):
            verify_fit(raw[:-4])


if __name__ == "__main__":
    unittest.main()
