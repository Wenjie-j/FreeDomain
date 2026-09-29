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
`kmod-tun`, `kmod-nft-tproxy`, the proxy core, OpenClash, mwan3/LuCI and the NSS/Wi-Fi stack. A
package name in `.config` is insufficient: the built manifest and root tree
must contain it. The root tree must also contain a ported setup service,
firewall4 backend and status page; simple static checks block the known legacy
iptables service. These checks are only an inventory, not functional proof.
A Sing-box file in the root tree is also insufficient:
`--core-build-report` must identify the V4 base and pinned 1.14.1 source,
target architecture, required build tags and the staged binary SHA-256.
This is a declared offline build trace, not proof of hardware runtime or
cryptographic supply chain attestation. Neither this gate nor the inherited OTA gates prove runtime
1GiB RAM, radio calibration, live NSS acceleration, migration, or recovery.

The September 27 plugin archive contains code but also private node/config
data. Do not commit the archive, generated configurations, URLs or credentials.
The September 29 source-only export has now been received and audited. Its
SHA-256 is `e8baf87d0aaa761bc01879c28eacc2d185d7713d2c43d21c53206ba7ca88c8e0`.
It contains the later node-test controller, manager and page, but not the
`sing-box-setup` service that those files call. A separate September 29 service
export, SHA-256 `1c5f726d47b32b4722aba55ffa9cdeaec9dddf7af92c5d0e188dd7690e435893`,
supplies that script. It waits for the proxy and DNS ports, invokes the old
firewall and writes a runtime dnsmasq include. This confirms the old service
contract; it does not validate the new dnsmasq inclusion or firewall backend.
The old firewall implementation
uses iptables/ipset and has a fixed private upstream endpoint. It cannot be
used as a firewall4/NSS/mwan3 backend. The status page also checks an iptables
chain. The rule updater downloads `geoip-cn.srs`, while the old firewall reads
`geoip-cn.json`; V4 must generate a verified nftables list from the same
release and preserve a working copy on update failure. See
`CN-NSS-ACCEPTANCE.md` for the distinct domestic-direct and actual NSS
hardware-acceleration tests. The service and firewall replacement remain
blocking work.
`collect-current-ui.sh` gathers only controller/view/manager and service scripts
into `/tmp`; it excludes `/etc/config`, `/etc/sing-box` and the executable core.

`audit_current_singbox_ui.py` inspects the private archive without extracting
it, and emits a fixed vocabulary JSON report with no node or subscription
contents. `prepare_current_singbox_ui.py` makes a private, offline working copy
of five UI/backend source files (plus the setup service when supplied). It changes each mutation route to LuCI's
POST-only dispatcher action and checks the method again in `require_post()`;
the read-only `list` route stays GET. Its status page checks the proposed
firewall4 chain names and the generated dnsmasq include rather than the old
iptables chain or UCI input. The staged setup service calls a future
`sing-box-firewall4` executable and refuses to start when generated dnsmasq
configuration does not include its runtime file. This is a fail-closed candidate:
that executable has not been implemented, and the generated dnsmasq path is
not yet verified on the V4 target. It excludes the legacy firewall and rules
scripts, and labels the output `OFFLINE-ONLY.json`. Neither script stages a
package in the image or relaxes the V4 and OTA gates. Example, using a private
local copy of the archive:

```sh
python3 arthur-build/v4/audit_current_singbox_ui.py \
  /private/path/current-ui.tar.gz \
  --services-archive /private/path/current-services.tar.gz
python3 arthur-build/v4/prepare_current_singbox_ui.py \
  /private/path/current-ui.tar.gz \
  --services-archive /private/path/current-services.tar.gz \
  --output /private/path/v4-ui-candidate
```

The active page's JavaScript already uses POST for mutations and GET for the
list, so the method restriction preserves its existing interaction. Before
packaging, implement and validate the firewall4 backend, confirm the dnsmasq
include on a V4 image, test LuCI Lua compatibility, and verify service restart,
node import/test, DNS and proxy behavior on a test image and device.

`render_firewall4_draft.py` is the first offline firewall4 rule candidate. It
renders a partial nftables file for inclusion *inside* `table inet fw4`, using
the old IPv4 bypass ranges, a validated CN CIDR set, TCP redirect, UDP TPROXY,
LAN DNS redirect and the old LAN IPv6 forward block. It requires a separately
provided LAN device, the active proxy endpoint IPv4 and at least 5000 valid CN
IPv4 networks. The endpoint is an explicit private local input, kept ahead of
the CN set in both bypass paths; no endpoint is embedded in repository source.
The generated draft is private and must track endpoint changes. Do not put it in
`/etc/nftables.d/`: target `fw4 check`, policy routing mark/table allocation,
mwan3 mark overlap, NSS acceleration, service reload and real traffic tests
have not been done. This is not yet `/usr/bin/sing-box-firewall4` and cannot
satisfy the V4 component gate. OpenWrt's firewall4 includes
`/etc/nftables.d/*.nft` within its generated table; the Linux kernel documents
the separate TPROXY mark and local policy route required for delivery.

The old TPROXY mark was `0x66/0xff`: it changed only the low byte. The draft
now uses nft's masked mark update to preserve the other bits, including a
typical mwan3 high-bit mask. `check_firewall4_mark_space.py` is a read-only
offline screen for copied `ip -4 rule show`, `ip -4 route show table 166`,
`fw4 print` and the actual `mwan3.globals.mmx_mask`. It reports collision
codes without echoing route or firewall contents and *always* denies live
activation. Absence of a collision in copied text cannot prove live priority,
reload behavior, NSS acceleration or routing correctness. No start/stop
firewall4 service exists yet.

`firewall4_transaction_model.py` now exercises the proposed start/stop order
against a simulated adapter: preflight, validate the candidate without live
installation, add the local table 166 route and masked `0x66/0xff` rule, stage
the private include, `fw4 check`, reload, verify
chains; failures remove the include, reload to remove live proxy rules, then
release only the routing resources acquired in that attempt. A failed rollback
retains the local route so packets are not left with a live TPROXY rule and no
delivery path. Stop requires proof of ownership before removing anything and
removes the route only after firewall reload and chain absence checks. This
module has no CLI or OpenWrt command adapter and cannot be installed as
`/usr/bin/sing-box-firewall4`. The real adapter still needs durable ownership
state, reboot reconciliation, coordination with concurrent firewall reloads,
exact `fw4`/`ip`/`nft` behavior on the V4 target,
and failure injection on a recoverable test image.

`check_dnsmasq_include.py` looks only at a *copied generated* dnsmasq config,
not the old UCI input. The old setup writes
`/tmp/dnsmasq.d/99-arthur-singbox.conf`; if the generated config does not
explicitly include that file or directory, DNS migration blocks. A matching
line still requires an active-process and functional lookup test. No generated
V4 dnsmasq config is available yet, so this condition remains unverified.

`prepare_cn_firewall_candidate.py` now accepts the exact `geoip-cn.srs` used
by Sing-box and calls a runnable Sing-box 1.14.1 `rule-set decompile` into a
temporary JSON. It validates the CIDRs and generates the nftables draft from
that same source, requiring the proxy endpoint IPv4 and reporting SHA-256 and
count without writing a JSON beside
the source. It refuses to replace an earlier output. The V4 ARM binary cannot
run on an unrelated build host, so this step needs a host-native 1.14.1 build
or an isolated V4 test environment. No real `.srs` was supplied in the source
only exports; synthetic failure and provenance tests pass, while actual
binary decompilation and `fw4 check` remain pending.

Primary references:
- https://github.com/openwrt/firewall4/blob/master/root/usr/share/firewall4/templates/ruleset.uc
- https://docs.kernel.org/networking/tproxy.html

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
| Sing-box core | `SagerNet/sing-box` v1.14.1 source; OpenWrt package recipe | Rebuild for V4 toolchain, verify tags and custom service |
| mwan3 | `openwrt/packages/net/mwan3` | Validate firewall4, DNS, proxy and NSS behavior |
| LuCI mwan3 + compatibility | `openwrt/luci/applications/luci-app-mwan3`, `modules/luci-compat` | Interactive acceptance test |
| Argon | `jerrykuku/luci-theme-argon` external feed | Pin compatible source and preserve existing style |
| Existing custom UI | User's later source-only export | Port backend calls; keep pages and behavior |

These package definitions establish a build path, not functional compatibility.

`feeds.lock.json` records eight immutable candidate feed commits; run
`write_pinned_feeds.py --output /path/to/isolated-openwrt/feeds.conf` before
updating feeds. The selected packages feed defines Sing-box 1.14.0. The user's
current Sing-box 1.14.1 executable was built for the old Linux 4.4 firmware;
version equality would not establish V4 compatibility. The official v1.14.1
source tag is pinned separately in the lock for a new package build with the
V4 toolchain, required feature tags and service hooks. Its mwan3 2.12.2 declares iptables
dependencies, so firewall4/NSS/proxy interaction is unverified. The lock
therefore does **not** authorize a V4 image build or distribution.

`candidate.config.fragment` and `prepare_candidate_config.py` stage the
available UI, multi-WAN, TUN and Mesh packages on an offline V3 config copy.
The fragment deliberately excludes Sing-box until the core has been rebuilt
and the current custom UI source can be integrated. Run `make defconfig` in the
isolated tree and compare the effective config and produced manifest; the
fragment alone does not prove a package built or that its UI works.

The official v1.14.1 source archive is pinned by SHA-256 in `feeds.lock.json`.
`prepare_singbox_recipe.py` verifies its root `go.mod` (Go 1.25.5 minimum) and
changes only the version/hash in the reviewed 1.14.0 OpenWrt package recipe.
The current candidate packages feed defaults to Go 1.27; actual cross-build
and runtime compatibility remain untested. `singbox-1.14.1.config.fragment`
records the old core's five required feature tags, but is not applied by the
base config staging script. No old Linux 4.4 binary is copied into V4.

`luci-app-arthur-overview/` is the first Chinese LuCI page draft. It refreshes
read-only mwan3, netifd and wireless status and links only to status pages.
See `UI-CONTRACT.md` for the eventual dual WAN, Mesh, NSS and core updater
interactions and the hardware validation conditions required before writes.

Example offline check:

```sh
python3 arthur-build/v4/verify_components.py \
  --artifact Arthur-612-NSS11.4-V3-20260928.zip \
  --output v4-component-gate.json
```
