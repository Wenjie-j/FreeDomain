#!/bin/sh
# Arthur AP-CP03-C1 boot-slot evidence collector. READ ONLY.
set -eu
umask 077

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'run as root'
for tool in id date uname cat dd wc awk grep sed tr tar sha256sum mktemp rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

BOARD=''
[ ! -r /tmp/sysinfo/board_name ] || BOARD="$(cat /tmp/sysinfo/board_name)"
[ "$BOARD" = 'ap-cp03-c1' ] || fail "unexpected board: ${BOARD:-unknown}"

for entry in '2:512' '3:512' '12:512'; do
    part="${entry%%:*}"
    expected_sectors="${entry#*:}"
    size_file="/sys/class/block/mmcblk0p${part}/size"
    [ -r "$size_file" ] || fail "missing mmcblk0p${part} size"
    actual_sectors="$(cat "$size_file")"
    [ "$actual_sectors" = "$expected_sectors" ] \
        || fail "unexpected mmcblk0p${part} size: $actual_sectors sectors"
    [ -r "/dev/mmcblk0p${part}" ] || fail "cannot read /dev/mmcblk0p${part}"
done

STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d /tmp/arthur-boot-slot.XXXXXXXX)" \
    || fail 'cannot create temporary directory'
OUT="/tmp/Arthur-Boot-Slot-Evidence-${STAMP}.tar.gz"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

read_partition() {
    device="$1"
    output="$2"
    case "$device:$output" in
        /dev/mmcblk0p2:BOOTCONFIG-p2.img|\
        /dev/mmcblk0p3:BOOTCONFIG1-p3.img|\
        /dev/mmcblk0p12:APPSBLENV-p12.img) ;;
        *) fail 'partition read request is outside the fixed allowlist' ;;
    esac
    dd if="$device" of="$WORK/$output" bs=4096 count=64 2>"$WORK/$output.dd.txt" \
        || fail "failed to read $device"
    bytes="$(wc -c <"$WORK/$output" | tr -d ' ')"
    [ "$bytes" = 262144 ] || fail "$device capture is not 262144 bytes"
}

say 'Arthur boot-slot evidence collector (READ ONLY)'
say 'Reading only p2 BOOTCONFIG, p3 BOOTCONFIG1 and p12 APPSBLENV.'
say 'No flash write, GPT change, boot-variable change, service restart or reboot.'

read_partition /dev/mmcblk0p2 BOOTCONFIG-p2.img
read_partition /dev/mmcblk0p3 BOOTCONFIG1-p3.img
read_partition /dev/mmcblk0p12 APPSBLENV-p12.img

{
    say 'classification=READ_ONLY_PRIVATE_BOOT_SLOT_EVIDENCE'
    say "created=$STAMP"
    say "board=$BOARD"
    uname -a
    printf 'cmdline='; cat /proc/cmdline 2>/dev/null || true; printf '\n'
    say 'partition_bytes=262144'
    if [ -r /etc/fw_env.config ]; then
        printf 'fw_env_config='; tr '\n' ' ' </etc/fw_env.config; printf '\n'
    fi
    if command -v fw_printenv >/dev/null 2>&1; then
        for key in bootcmd bootargs bootdelay bootcount bootlimit boot_part \
                   boot_partition boot_slot active_slot active_partition \
                   upgrade_available tries_remaining bootmode boot_state; do
            value="$(fw_printenv -n "$key" 2>/dev/null || true)"
            [ -z "$value" ] || printf '%s=%s\n' "$key" "$value"
        done
    fi
} >"$WORK/system.txt"

(
    cd "$WORK"
    sha256sum BOOTCONFIG-p2.img BOOTCONFIG1-p3.img APPSBLENV-p12.img \
        system.txt >SHA256SUMS.txt
    sha256sum -c SHA256SUMS.txt >/dev/null
    tar -czf "$OUT" BOOTCONFIG-p2.img BOOTCONFIG1-p3.img \
        APPSBLENV-p12.img system.txt SHA256SUMS.txt
) || fail 'failed to create evidence archive'

tar -tzf "$OUT" >/dev/null || fail 'archive verification failed'
say 'SUCCESS: private read-only evidence collected.'
say "File: $OUT"
sha256sum "$OUT"
say 'This archive contains raw boot metadata. Send it privately; never publish it.'
say 'Do not flash, erase, repair GPT, change boot variables or reboot for this test.'
