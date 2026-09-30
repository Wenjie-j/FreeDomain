"""Bounded, non-executing structural checks for a candidate ARM64 proxy core.

ELF constants/layout: Linux v6.12 include/uapi/linux/elf.h. These checks
cannot prove origin, CPU/kernel/libc compatibility, or working proxy behavior.
"""

import struct
from pathlib import Path


MAX_BINARY = 128 * 1024 * 1024


def inspect_arm64_elf(data: bytes) -> dict:
    if len(data) < 64 or len(data) > MAX_BINARY:
        raise ValueError("core executable size is outside inspection bounds")
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("core must be an ELF64 little-endian executable")
    (_, kind, machine, version, entry, phoff, _, _, ehsize,
     phentsize, phnum, _, _, _) = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if machine != 183 or kind not in (2, 3) or version != 1 or ehsize != 64:
        raise ValueError("core must be an ARM64 executable with a valid ELF header")
    # Extended phnum requires section-table parsing, outside this checker.
    if (phentsize != 56 or not 1 <= phnum <= 4096 or phoff < 64
            or phoff + phnum * phentsize > len(data)):
        raise ValueError("core program-header table is invalid or truncated")
    loads = 0
    executable_entry = False
    interpreter = False
    for index in range(phnum):
        ptype, flags, offset, address, _, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize)
        if offset + filesz > len(data):
            raise ValueError("core segment extends beyond executable bytes")
        if ptype == 3:
            interpreter = True
        if ptype != 1:
            continue
        loads += 1
        if filesz > memsz or address + memsz > 1 << 64:
            raise ValueError("core load segment has invalid memory bounds")
        if align not in (0, 1) and (align & (align - 1) or (address - offset) % align):
            raise ValueError("core load segment has invalid alignment")
        if flags & 1 and address <= entry < address + filesz:
            executable_entry = True
    if not loads or not executable_entry:
        raise ValueError("core entry point is not in a file-backed executable segment")
    return {"elf_class": "ELF64", "endianness": "little", "machine": "aarch64",
            "elf_type": "EXEC" if kind == 2 else "DYN", "load_segments": loads,
            "interpreter_declared": interpreter, "runtime_verified": False}


def read_core_file(path: Path) -> tuple[bytes, dict]:
    if (path.is_symlink() or not path.is_file() or not path.stat().st_mode & 0o111
            or not 64 <= path.stat().st_size <= MAX_BINARY):
        raise ValueError("core file must be a bounded regular executable")
    data = path.read_bytes()
    return data, inspect_arm64_elf(data)
