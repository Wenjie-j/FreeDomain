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

Example offline check:

```sh
python3 arthur-build/v4/verify_components.py \
  --artifact Arthur-612-NSS11.4-V3-20260928.zip \
  --output v4-component-gate.json
```
