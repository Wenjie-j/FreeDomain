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
`--package-file-owners` additionally requires file lists from built packages:
the core package must own only the binary among these sensitive paths, while
the custom UI, service and firewall backend must have separate package owners.
Without a report the ownership checks remain `NOT_INSPECTED` and block. A
declaration does not prove the package archive contents; derive this report
from actual package files when V4 packages exist.
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

The offline porter also moves the node-manager UCI update after a successful
service restart. If restart fails, it checks both the old config copy and the
old service restart before claiming recovery, otherwise it reports the exact
remaining failure. This was checked against the user's source-only export and
local tests; no live service or Lua integration test has been run.
The staged DNS setup now creates a hash ownership marker alongside its own
runtime dnsmasq file. It refuses to overwrite an existing unowned file and
refuses to delete an unowned, symlinked or modified file on stop. The status
page checks the same marker before reporting the DNS include as present.
Shell tests exercise a foreign file, a modified file, a symlink and a normal
start/stop cycle. These are offline checks, not an endorsement of the future
firewall4 or dnsmasq runtime behavior.

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
delivery path. Stop requires proof of ownership and inspects the reserved
rule/table before removing anything. It removes only present owned routing
after firewall reload and chain absence checks, allowing a stop after reboot
when volatile routing has not yet been restored. This
module has no CLI or OpenWrt command adapter and cannot be installed as
`/usr/bin/sing-box-firewall4`. The real adapter still needs durable ownership
state, reboot reconciliation, coordination with concurrent firewall reloads,
exact `fw4`/`ip`/`nft` behavior on the V4 target,
and failure injection on a recoverable test image.

`firewall4_sandbox_adapter.py` connects that model to command-shaped calls
and private include files *only inside* a marked test root, with an
explicit injected fake command runner. It checks copied live-state output for
mark/table conflicts and records a digest-based ownership marker; a changed
include blocks stop rather than deleting someone else's rule. It rejects a
missing simulation marker and a real command runner. The tests exercise a
second adapter instance for stop, conflicts, tampering and reload failure.
This adapter has no CLI or supplied real `fw4`, `ip` or `nft` runner, and must not
be copied into firmware. A boot-safe target adapter and target `fw4 check`
remain unimplemented.

The offline `reconcile_after_boot()` path now checks the persistent include's
ownership digest and the exact reserved rule/table contents before restoring
missing volatile route/rule entries, reloading and verifying chains. A foreign
entry or changed include blocks without touching it. This models a clean
reboot only: firewall4 may load the persistent include before the proxy and
policy route are ready, so startup ordering and interrupted-boot recovery
remain unproved. It is not an automatic firmware rollback mechanism.

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

`feeds.lock.json` records seven immutable feed commits and a separate pinned
Argon package repository. Run
`write_pinned_feeds.py --output /path/to/isolated-openwrt/feeds.conf` before
updating feeds, then clone Argon at the locked commit under the build tree's
`package/` directory. Its `Makefile` lives at repository root, so an ordinary
OpenWrt feed would not discover that package. The selected packages feed
defines Sing-box 1.14.0. The user's
current Sing-box 1.14.1 executable was built for the old Linux 4.4 firmware;
version equality would not establish V4 compatibility. The official v1.14.1
source tag is pinned separately in the lock for a new package build with the
V4 toolchain, required feature tags and service hooks. Its mwan3 2.12.2 declares iptables
dependencies, so firewall4/NSS/proxy interaction is unverified. The lock
therefore does **not** authorize a V4 image build or distribution.

`candidate.config.fragment` and `prepare_candidate_config.py` stage the
available UI, multi-WAN, TUN, nft TPROXY and Mesh packages on an offline V3
config copy. The nft TPROXY selection is required by the V4 component gate.
The fragment deliberately excludes Sing-box until the core has been rebuilt
and the current custom UI source can be integrated. Run `make defconfig` in the
isolated tree and compare the effective config and produced manifest; the
fragment alone does not prove a package built or that its UI works.

The official v1.14.1 source archive is pinned by SHA-256 in `feeds.lock.json`.
`prepare_singbox_recipe.py` verifies either that archive or the pinned Git
commit and tag, including its `go.mod` (Go 1.25.5 minimum), and changes only
the version/hash and the reviewed install/conffiles blocks in the pinned 1.14.0
OpenWrt package recipe. It refuses an unexpected change to those blocks. The resulting
`package/sing-box/Makefile` is a prepared overlay for the pinned packages feed;
place it at `feeds/packages/net/sing-box/Makefile` inside an isolated V4 build
tree after fetching the locked feeds. Its relative Go package include requires
that location.
When prepared from a Git object, the archive hash still needs verification by
the build tree's `make download`; the cloud preflight below also checks the
pinned source archive. The prepared package installs only `/usr/bin/sing-box`:
the upstream defaults for `/etc/init.d/sing-box`, `/etc/config/sing-box` and
`/etc/sing-box/config.json` would collide with the user's existing service
contract. The custom init/setup service and configuration migration must be
ported and packaged separately; the V4 component gate remains blocked without
those files. This core-only package must not be used as a stand-alone upgrade
on the running Linux 4.4 router.
The current candidate packages feed defaults to Go 1.27; actual cross-build
and runtime compatibility remain untested. `singbox-1.14.1.config.fragment`
records the old core's five required feature tags, but is not applied by the
base config staging script. Applying it after the candidate fragment to a
copy of the real V3 `final.config` selects the core and all five tags exactly
once in an offline check; `make defconfig` and a package build are still needed
to test whether the selected packages resolve. No old Linux 4.4 binary is
copied into V4.

The isolated core-package build in run `36555424005` succeeded. It uploaded
`sing-box-1.14.1-r1.apk` for `aarch64_cortex-a53` with SHA-256
`d83724e7bdc4d1fb4ff7e49cf75f596b9e0faceff73f251f5b3b3456a2739a8e`.
The build checked that the staged package root contains the executable and
does not contain upstream init/config defaults; this is not a firmware image.
`report_core_package.py` now requires the staged package file list to contain
only `usr/bin/sing-box`, checks its ELF header and selected architecture/tags,
and emits a binary hash build trace and a partial file-owners report alongside
the APK on the next build. The partial report deliberately lacks custom service
owners, so the complete image gate stays blocked. This new reporting step
has only local tests until a new cloud build completes.

`.github/workflows/arthur-v4-config-preflight.yml` now checks out the pinned
base and feeds, stages Argon as a package, downloads and verifies the pinned
Sing-box source archive, compares the generated 1.14.1 recipe byte for byte
with the committed overlay, and runs `make defconfig` on a V3-equivalent NSS
seed plus the V4 fragments. The first cloud run retained all 18 checked
selections (run `36537038227`). The next stage compiles the Sing-box package
with the V4 toolchain and records a package digest if successful. It does not
produce a firmware image; even a green run cannot authorize upgrading the
router. The source-only custom UI and target firewall4 backend are not
installed by this job. Its config preflight uses the pinned NSS seed rather
than the exact V3 `final.config`, so later image builds must recheck their
effective config and manifest.
The first package-compile attempt (run `36537514745`) stopped while preparing
host Lua because `staging_dir/host/bin/libdeflate-gzip` was missing. The
workflow now installs OpenWrt host tools and the target toolchain before
requesting the selected package. That run also printed Kconfig dependency
cycles from packages installed by `feeds install -a`, including the unrelated
audio package `squeezelite-custom` and a chain involving `mwan3`, legacy
iptables packages, and NSS PPPoE. Its checked symbols survived `defconfig`,
which alone did not make those cycles acceptable. The next preflight installs
only selected V4 feed packages plus their recursive dependencies, and blocks
on any remaining recursive Kconfig diagnostic. It still does not validate
the legacy mwan3 firewall rules against firewall4, TPROXY or NSS runtime.
The second package attempt (run `36538831447`) installed host tools and the
cross toolchain, then stopped when the `gpio-button-hotplug` dependency
required the as-yet ungenerated Linux 6.12 kernel `.config`. The workflow now
builds `target/linux/compile` before the selected package, which should
generate that configuration and kernel dependencies. This has not yet passed
a cloud run; no V4 Sing-box package or firmware image has been produced.

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
