#!/bin/sh
# Arthur AP-CP03-C1 legacy network evidence collector. READ ONLY.
set -eu
umask 077

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'run as root'
for tool in id date uname cat uci ip tar sha256sum mktemp rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

BOARD=''
[ ! -r /tmp/sysinfo/board_name ] || BOARD="$(cat /tmp/sysinfo/board_name)"
[ "$BOARD" = 'ap-cp03-c1' ] || fail "unexpected board: ${BOARD:-unknown}"

STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d /tmp/arthur-network.XXXXXXXX)" \
    || fail 'cannot create temporary directory'
OUT="/tmp/Arthur-Legacy-Network-Evidence-${STAMP}.tar.gz"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

capture() {
    name="$1"
    shift
    "$@" >"$WORK/$name" 2>&1 || true
}

say 'Arthur legacy network evidence collector (READ ONLY)'
say 'No UCI write, firewall change, daemon control, flash access or system restart.'

# This may contain private addresses and ISP credentials. It stays inside the
# private archive; the collector never prints the contents to the terminal.
uci -q show network >"$WORK/uci-network.txt" \
    || fail 'cannot read UCI network configuration'
capture ip-link.txt ip -details -o link show
capture ip4-address.txt ip -4 -o address show
capture ip6-address.txt ip -6 -o address show
capture ip4-route.txt ip -4 route show table all
capture ip6-route.txt ip -6 route show table all
capture ip4-rule.txt ip -4 rule show
capture ip6-rule.txt ip -6 rule show

if command -v bridge >/dev/null 2>&1; then
    capture bridge-link.txt bridge -details link show
    capture bridge-vlan.txt bridge vlan show
fi
if command -v ubus >/dev/null 2>&1; then
    capture ubus-system-board.json ubus call system board
    capture ubus-network-interface.json ubus call network.interface dump
    capture ubus-network-device.json ubus call network.device status
fi
if [ -r /etc/board.json ]; then
    cat /etc/board.json >"$WORK/board.json"
fi

{
    say 'classification=READ_ONLY_PRIVATE_LEGACY_NETWORK_EVIDENCE'
    say "created=$STAMP"
    say "board=$BOARD"
    uname -a
    printf 'cmdline='; cat /proc/cmdline 2>/dev/null || true; printf '\n'
} >"$WORK/system.txt"

(
    cd "$WORK"
    sha256sum ./* >SHA256SUMS.txt
    sha256sum -c SHA256SUMS.txt >/dev/null
    tar -czf "$OUT" ./*
) || fail 'failed to create evidence archive'

tar -tzf "$OUT" >/dev/null || fail 'archive verification failed'
say 'SUCCESS: private read-only network evidence collected.'
say "File: $OUT"
sha256sum "$OUT"
say 'This archive may contain ISP credentials, addresses and MAC addresses.'
say 'Send it privately; never publish it or attach it to a public GitHub issue.'
