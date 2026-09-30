#!/bin/sh
# Private proxy configuration collector for the Arthur Linux 4.4 system.
set -eu
umask 077

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'run as root'
for tool in id date cat find cp mkdir tar sha256sum mktemp rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done
[ -r /tmp/sysinfo/board_name ] || fail 'board name unavailable'
[ "$(cat /tmp/sysinfo/board_name)" = 'ap-cp03-c1' ] || fail 'unexpected board'

STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d /tmp/arthur-proxy.XXXXXXXX)" || fail 'cannot create work directory'
OUT="/tmp/Arthur-Legacy-Proxy-Evidence-${STAMP}.tar.gz"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

copy_file() {
    source="$1"
    [ -f "$source" ] && [ ! -L "$source" ] || return 0
    relative="${source#/}"
    mkdir -p "$WORK/${relative%/*}"
    cp -p "$source" "$WORK/$relative"
}

copy_tree_files() {
    root="$1"
    [ -d "$root" ] && [ ! -L "$root" ] || return 0
    find "$root" -type f | while IFS= read -r source; do
        copy_file "$source"
    done
}

say 'Arthur legacy proxy evidence collector (PRIVATE, READ ONLY).'
say 'No UCI write, service restart, firewall change, package install or flash access.'
copy_file /etc/config/singbox
copy_file /etc/config/openclash
copy_tree_files /etc/sing-box
# Preserve user data while excluding OpenClash's old core and transient history.
for directory in config custom proxy_provider rule_provider backup; do
    copy_tree_files "/etc/openclash/$directory"
done

[ -f "$WORK/etc/config/singbox" ] || fail 'custom Sing-box UCI config missing'
[ -f "$WORK/etc/config/openclash" ] || fail 'OpenClash UCI config missing'
cat >"$WORK/CLASSIFICATION.txt" <<'EOF'
PRIVATE_LEGACY_PROXY_CONFIGURATION_NOT_PUBLIC_NOT_RESTORE_APPROVAL
Old executable cores and runtime firewall state are excluded.
EOF
(
    cd "$WORK"
    find CLASSIFICATION.txt etc -type f -exec sha256sum {} \; >SHA256SUMS.txt
    sha256sum -c SHA256SUMS.txt >/dev/null
    tar -czf "$OUT" CLASSIFICATION.txt SHA256SUMS.txt etc
) || fail 'failed to build verified private archive'
tar -tzf "$OUT" >/dev/null || fail 'archive verification failed'
say 'SUCCESS: private proxy migration evidence collected.'
say "File: $OUT"
sha256sum "$OUT"
say 'Contains private nodes, subscriptions and provider data. Send privately only.'
