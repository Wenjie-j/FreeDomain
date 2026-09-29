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
