#!/bin/sh
# Source-only snapshot for porting the existing Sing-box LuCI frontend.
# Reads existing files and writes one archive under /tmp. No router config,
# node database, subscriptions, service restarts, or partition writes.
set -eu
umask 077

stamp="$(date +%Y%m%d-%H%M%S)"
output="/tmp/Arthur-Current-Singbox-UI-${stamp}.tar.gz"
set --
for file in \
  usr/lib/lua/luci/controller/singbox.lua \
  usr/lib/lua/luci/view/singbox/nodes.htm \
  usr/lib/lua/luci/model/cbi/singbox.lua \
  usr/lib/lua/luci/model/cbi/singbox_status.lua \
  usr/lib/lua/singbox/manager.lua \
  etc/init.d/sing-box \
  usr/bin/sing-box-node-manager \
  usr/bin/sing-box-switch-node \
  usr/bin/sing-box-rollback \
  usr/bin/sing-box-firewall; do
  if [ -f "/$file" ]; then
    set -- "$@" "$file"
  fi
done
if [ "$#" -eq 0 ]; then
  echo 'No expected UI source files found; no archive created.' >&2
  exit 1
fi
tar -C / -czf "$output" "$@"
echo "Archive: $output"
sha256sum "$output"
echo "Included files: $# (source and service scripts only)"
