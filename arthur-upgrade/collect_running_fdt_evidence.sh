#!/bin/sh
# JDCloud Arthur / AP-CP03-C1 running-FDT and RAM evidence (READ ONLY).
# Does not write to firmware, boot slots, GPT, router config or services.
set -eu
umask 077

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'Please log in as root.'
for tool in id cat date uname dd wc tr grep tar sha256sum mktemp rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "Missing utility: $tool"
done
[ -r /tmp/sysinfo/board_name ] || fail 'Missing board identification.'
BOARD="$(cat /tmp/sysinfo/board_name)"
[ "$BOARD" = 'ap-cp03-c1' ] || fail "Unexpected board: $BOARD"
[ -r /sys/firmware/fdt ] || fail 'Running FDT not exposed; no safe inference is possible.'
[ -r /proc/meminfo ] || fail 'Cannot read /proc/meminfo.'

STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d /tmp/arthur-running-fdt.XXXXXXXX)" || fail 'Unable to create temporary directory.'
OUT="/tmp/Arthur-Runtime-FDT-$STAMP.tar.gz"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

say 'Collecting running FDT and memory information (READ ONLY).'
dd if=/sys/firmware/fdt of="$WORK/running-fdt.dtb" bs=4096 count=256 2>"$WORK/fdt-read.txt" || fail 'Unable to read running FDT.'
BYTES="$(wc -c <"$WORK/running-fdt.dtb" | tr -d ' ')"
[ "$BYTES" -ge 40 ] && [ "$BYTES" -lt 1048576 ] || fail 'Running FDT is too small or may have been truncated.'
grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo >"$WORK/memory-summary.txt" || fail 'Unable to read memory summary.'
grep -q '^MemTotal:' "$WORK/memory-summary.txt" || fail 'MemTotal is missing.'
{
    say 'classification=PRIVATE_READ_ONLY_RUNNING_FDT_NOT_FLASH_APPROVAL'
    say "board=$BOARD"
    say "captured=$STAMP"
    printf 'kernel='; uname -r
    say "fdt_bytes=$BYTES"
    say 'note=Running FDT is not proof of bootloader, rollback or OTA safety.'
} >"$WORK/metadata.txt"
(
    cd "$WORK"
    sha256sum running-fdt.dtb memory-summary.txt metadata.txt >SHA256SUMS.txt
    sha256sum -c SHA256SUMS.txt >/dev/null
    tar -czf "$OUT" running-fdt.dtb memory-summary.txt metadata.txt SHA256SUMS.txt
) || fail 'Archive creation failed.'
tar -tzf "$OUT" >/dev/null || fail 'Archive verification failed.'
say "SUCCESS: $OUT"
sha256sum "$OUT"
say 'PRIVATE archive: FDT may contain MAC addresses and hardware identifiers.'
say 'Do not upload to a public GitHub repository.'
say 'No flash writes, partition edits, service restarts or reboots were performed.'
