# Arthur 1GiB — read-only OTA release gate

This is an **offline preflight**, **not a flash utility**. It does not connect to or write to the router.

It checks the kernel FIT and rootfs layout in a GitHub Actions artifact ZIP and evaluates the observed boot/storage baseline. The FIT's configured kernel and device tree subimage hashes must match; this is an integrity check against the digests carried inside the FIT, not publisher authentication or a signature check.

The selected FIT device tree is also inspected for a 64-bit `/memory/reg` map.
An explicit 512 MiB map blocks this 1 GiB router; an absent memory node is
reported as bootloader-dependent and still blocked pending runtime proof.
An explicit 1 GiB map is only a static declaration, not a boot test. In the
saved September 28 evidence, the original p16 FIT declares 512 MiB, the
running 4.4 FDT declares 1 GiB, and the V3 FIT has no explicit memory node.
Therefore the V3 artifact reports `BOOTLOADER_DEPENDENT_NO_MEMORY_NODE` and
`UNVERIFIED_1G_FIT_MEMORY_MAP`; it must not be used for a production upgrade.

**A matching FIT smaller than 6 MiB does NOT mean the firmware is safe to flash.** Our production router has p16 HLOS, p17 HLOS_1 (unverified bootability), p18 rootfs, *no rootfs_1*, no validated fallback GPT and no demonstrated full-firmware rollback. The program deliberately emits \`NO_GO_FOR_PRODUCTION_ROUTER\` until a separate, proven migration-and-recovery implementation exists. It has no "force" or "approve" switch.

To run the offline checks:

\`\`\`sh
python3 arthur-build/ota/ota_release_gate.py \
  --artifact /path/to/Arthur-612-NSS11.4-V3-20260928.zip \
  --baseline arthur-build/ota/baseline.json

python3 -m unittest discover -s arthur-build/ota -p 'test_*.py' -v
\`\`\`

This release gate is a step toward the same Chinese LuCI upload/confirm/restart workflow as the original iStoreOS; it is **not** a replacement with serial/TFTP/manual flashing. See \`docs/ARTHUR-OTA-RELEASE-GATES.md\` for required recovery and config-migration tests.
