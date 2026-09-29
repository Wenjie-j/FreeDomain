# Arthur HLOS recovery evidence audit

`hlos_recovery_audit.py` performs bounded, read-only inspection of the saved
`p16-HLOS.img` and `p17-HLOS_1.img` captures.  It verifies the archive checksum
manifest, requires exact 6 MiB captures, verifies inline kernel/DTB FIT hashes
when a FIT begins at byte zero, and reports unexplained nonzero data or an
embedded SquashFS marker in the nominal backup partition.

It never writes a router, boot variable, GPT, or partition.  A valid FIT is not
proof that the bootloader can select or boot that slot, so every report remains
`BLOCKED_WRITE` until boot selection and recovery are separately demonstrated.

```sh
python3 arthur-upgrade/hlos_recovery_audit.py \
  --archive /path/to/Arthur-HLOS-p16-p17.tar.gz \
  --output /tmp/arthur-hlos-recovery-report.json
```

The report contains only structural evidence, sizes, offsets, and SHA-256
digests.  It does not extract filesystem contents or publish configuration.

`gpt_capture_audit.py` independently validates CRCs and geometry from saved
head/tail captures.  It detects a primary GPT that still points its backup
header at an earlier disk boundary and a missing terminal backup header:

```sh
python3 arthur-upgrade/gpt_capture_audit.py \
  --head /path/to/mmc-gpt-head-1MiB.bin \
  --tail /path/to/mmc-gpt-tail-1MiB.bin \
  --disk-bytes 7818182656 \
  --output /tmp/arthur-gpt-report.json
```

Even two valid GPT captures do not approve GPT repair; the device recovery path
must be proven separately.

## Combine the evidence with the firmware gate

The main upgrade gate accepts both sanitized reports and merges only recognized
blocker codes.  It never copies raw partition evidence or unknown fields into
its output.  Missing, malformed, spoofed, or unexpectedly permissive reports
fail closed:

```sh
python3 arthur-upgrade/upgrade_gate.py \
  --inventory arthur-upgrade/inventory-arthur-1gb-v3.json \
  --sysupgrade /path/to/sysupgrade.bin \
  --network-report /tmp/legacy-network-report.json \
  --hlos-recovery-report /tmp/arthur-hlos-recovery-report.json \
  --gpt-recovery-report /tmp/arthur-gpt-report.json \
  --output /tmp/arthur-combined-upgrade-gate.json
```

## Missing boot-slot evidence

The earlier filtered boot report proves that this router uses `bootcmd=bootipq`
and exposes no ordinary U-Boot slot variable. It did not capture the Qualcomm
BOOTCONFIG partitions. `collect_boot_slot_evidence.sh` is a BusyBox-ash
compatible collector with a fixed read allowlist: p2 BOOTCONFIG, p3
BOOTCONFIG1, and p12 APPSBLENV, each exactly 256 KiB. It refuses other boards
or partition sizes and writes only to a temporary directory and output archive.

The resulting archive contains raw boot metadata and must remain private. The
collector does not flash, repair GPT, set environment variables, restart a
service, or reboot the router.
