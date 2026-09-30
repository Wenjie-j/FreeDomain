import pathlib
import struct
import tempfile
import unittest

from core_elf import inspect_arm64_elf, read_core_file


def synthetic_arm64_elf():
    # Structural fixture only; never executed and contains no working core.
    data = bytearray(128)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0,
                     ident, 2, 183, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, 128, 128, 4096)
    return bytes(data)


class CoreELFTests(unittest.TestCase):
    def test_accepts_structurally_valid_exec_and_pie_without_claiming_runtime(self):
        data = bytearray(synthetic_arm64_elf())
        self.assertFalse(inspect_arm64_elf(data)["runtime_verified"])
        struct.pack_into("<H", data, 16, 3)
        self.assertEqual(inspect_arm64_elf(data)["elf_type"], "DYN")

    def test_rejects_wrong_machine_endianness_class_and_relocatable_objects(self):
        for offset, replacement in ((18, b"\x3e\x00"), (5, b"\x02"),
                                    (4, b"\x01"), (16, b"\x01\x00")):
            with self.subTest(offset=offset):
                data = bytearray(synthetic_arm64_elf())
                data[offset:offset + len(replacement)] = replacement
                with self.assertRaises(ValueError):
                    inspect_arm64_elf(data)

    def test_rejects_truncation_and_out_of_bounds_program_headers(self):
        for length in (4, 63, 80):
            with self.assertRaises(ValueError):
                inspect_arm64_elf(synthetic_arm64_elf()[:length])
        for offset, form, value in ((32, "<Q", 1000), (54, "<H", 8), (56, "<H", 0)):
            data = bytearray(synthetic_arm64_elf())
            struct.pack_into(form, data, offset, value)
            with self.assertRaises(ValueError):
                inspect_arm64_elf(data)

    def test_rejects_segment_bounds_alignment_and_non_executable_entry(self):
        for offset, form, value in ((96, "<Q", 129), (104, "<Q", 64),
                                   (112, "<Q", 3), (68, "<I", 4),
                                   (24, "<Q", 0x800000), (64, "<I", 4)):
            with self.subTest(offset=offset):
                data = bytearray(synthetic_arm64_elf())
                struct.pack_into(form, data, offset, value)
                with self.assertRaises(ValueError):
                    inspect_arm64_elf(data)

    def test_requires_executable_regular_file_not_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "core"
            path.write_bytes(synthetic_arm64_elf())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_core_file(path)
            path.chmod(0o755)
            self.assertEqual(read_core_file(path)[1]["machine"], "aarch64")
            link = pathlib.Path(directory) / "linked-core"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                read_core_file(link)


if __name__ == "__main__":
    unittest.main()
