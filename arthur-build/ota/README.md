# Arthur 1GiB — read-only OTA release gate

This is an **offline preflight**, **not a flash utility**. It does not connect to or write to the router.

It checks the kernel FIT and rootfs layout in a GitHub Actions artifact ZIP and evaluates the observed boot/storage baseline.

**A matching FIT smaller than 6 MiB does NOT mean the firmware is safe to flash.** Our production router has p16 HLOS, p17 HLOS_1 (unverified bootability), p18 rootfs, *no rootfs_1*, no validated fallback GPT and no demonstrated full-firmware rollback. The program deliberately emits \`NO_GO_FOR_PRODUCTION_ROUTER\` until a separate, proven migration-and-recovery implementation exists. It has no "force" or "approve" switch.

To run the offline checks:

\`\`\`sh
python3 arthur-build/ota/ota_release_gate.py \
  --artifact /path/to/Arthur-612-NSS11.4-V3-20260928.zip \
  --baseline arthur-build/ota/baseline.json

python3 -m unittest discover -s arthur-build/ota -p 'test_*.py' -v
\`\`\`

This release gate is a step toward the same Chinese LuCI upload/confirm/restart workflow as the original iStoreOS; it is **not** a replacement with serial/TFTP/manual flashing. See \`docs/ARTHUR-OTA-RELEASE-GATES.md\` for required recovery and config-migration tests.
