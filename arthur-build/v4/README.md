# V4 backend integration staging

This branch combines the V3 6.12/NSS build workflow with the two previously
separate read-only OTA gates. The V4 component gate checks the *actual image
manifest* and staged root filesystem before any candidate is described as
functionally integrated. It cannot authorize flashing.

The existing Chinese LuCI/Argon UI and custom Sing-box pages are the product
baseline. Port their backend calls to the newer LuCI/rpcd/ubus, firewall and
service interfaces while preserving the existing user flow. Add new interactive
pages only for dual WAN, Mesh, NSS status and independent Sing-box updates.

`verify_components.py` expects Argon, `luci-compat`, custom Sing-box source,
`kmod-tun`, the proxy core, OpenClash, mwan3/LuCI and the NSS/Wi-Fi stack. A
package name in `.config` is insufficient: the built manifest and root tree
must contain it. Neither this gate nor the inherited OTA gates prove runtime
1GiB RAM, radio calibration, live NSS acceleration, migration, or recovery.

The September 27 plugin archive contains code but also private node/config
data. Do not commit the archive, generated configurations, URLs or credentials.
The September 28 v2.1 node-test repair postdates that source snapshot; obtain
the latest source-only export before treating the UI port as complete.
`collect-current-ui.sh` gathers only controller/view/manager and service scripts
into `/tmp`; it excludes `/etc/config`, `/etc/sing-box` and the executable core.

`legacy_network_preflight.py` reads an offline `uci show` export and emits only
interface categories, safe field names and migration blockers. It deliberately
never maps old `eth*` to new `lan*`/`wan`, generates UCI, or changes the router.
Supply `--expected-management-ip` to compare the old LAN address without
printing it. It always blocks the first migration until real port mapping,
service behavior and recovery have been verified.
`--uci-show -` accepts an offline export on standard input without saving the
private source on disk.

## Source dependencies before a V4 build

The V3 workflow pins `qosmio/openwrt-ipq` at
`92a2d104145c8d265851c4b388a41bd8e9c21cd9`, but `feeds update -a`
fetches moving feed tips. Pin and record all feed revisions in the eventual V4
build, including packages, LuCI and the NSS feed, then record the resulting
manifest and build flags. Upstream package locations (availability only):

| Requirement | Candidate source | Integration still needed |
| --- | --- | --- |
| Sing-box core | `openwrt/packages/net/sing-box` | Compare version/features with user's 1.14.1 and custom service |
| mwan3 | `openwrt/packages/net/mwan3` | Validate firewall4, DNS, proxy and NSS behavior |
| LuCI mwan3 + compatibility | `openwrt/luci/applications/luci-app-mwan3`, `modules/luci-compat` | Interactive acceptance test |
| Argon | `jerrykuku/luci-theme-argon` external feed | Pin compatible source and preserve existing style |
| Existing custom UI | User's later source-only export | Port backend calls; keep pages and behavior |

These package definitions establish a build path, not functional compatibility.

`feeds.lock.json` records eight immutable candidate feed commits; run
`write_pinned_feeds.py --output /path/to/isolated-openwrt/feeds.conf` before
updating feeds. The selected packages feed defines Sing-box 1.14.0, whereas
the user's working core is 1.14.1. Its mwan3 2.12.2 declares iptables
dependencies, so firewall4/NSS/proxy interaction is unverified. The lock
therefore does **not** authorize a V4 image build or distribution.

`candidate.config.fragment` and `prepare_candidate_config.py` stage the
available UI, multi-WAN, TUN and Mesh packages on an offline V3 config copy.
The fragment deliberately excludes Sing-box until the exact core/features
and current custom UI source can be integrated. Run `make defconfig` in the
isolated tree and compare the effective config and produced manifest; the
fragment alone does not prove a package built or that its UI works.

Example offline check:

```sh
python3 arthur-build/v4/verify_components.py \
  --artifact Arthur-612-NSS11.4-V3-20260928.zip \
  --output v4-component-gate.json
```
