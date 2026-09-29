#!/usr/bin/env python3
"""Offline read-only compatibility gate. Never writes router flash or boot vars."""
from __future__ import annotations
import argparse, hashlib, json, struct, sys, tarfile
from pathlib import Path
from fit_integrity import inspect_fit_memory, verify_fit

LIMIT = 6 * 1024 * 1024
FIT_MAGIC = b'\xd0\x0d\xfe\xed'
REQUIRED_MARKERS = (b'config@cp03-c2', b'jdcloud,re-ss-01', b'JDC-RE-SS-01')
NETWORK_BLOCKERS = frozenset((
    'PHYSICAL_ETHERNET_MAPPING_UNVERIFIED',
    'FIRST_BOOT_RECOVERY_UNVERIFIED',
    'TUNNEL_SERVICE_MIGRATION_UNVERIFIED',
    'USB_WAN_MIGRATION_UNVERIFIED',
    'UNKNOWN_INTERFACE_BINDING',
    'LAN_OR_WAN_INTERFACE_MISSING',
    'MANAGEMENT_ADDRESS_REQUIRES_EXPLICIT_MIGRATION',
))
HLOS_RECOVERY_BLOCKERS = frozenset((
    'HLOS_NO_VERIFIED_FIT_AT_OFFSET_ZERO',
    'HLOS_1_NO_VERIFIED_FIT_AT_OFFSET_ZERO',
    'HLOS_1_CONTAINS_UNCLASSIFIED_NONZERO_DATA',
    'HLOS_1_SQUASHFS_MARKER_REQUIRES_CLASSIFICATION',
    'BOOT_SLOT_SELECTION_MECHANISM_NOT_CAPTURED',
    'HLOS_1_BOOT_NOT_PROVEN',
))
GPT_RECOVERY_BLOCKERS = frozenset((
    'PRIMARY_GPT_CAPTURE_INVALID',
    'PRIMARY_GPT_BACKUP_LBA_NOT_AT_CURRENT_DISK_END',
    'TERMINAL_BACKUP_GPT_HEADER_MISSING',
    'TERMINAL_BACKUP_GPT_CAPTURE_INVALID',
    'GPT_REPAIR_AND_RECOVERY_PATH_NOT_APPROVED',
))
BOOT_SLOT_BLOCKERS = frozenset((
    'BOOTCONFIG_COPIES_DIFFER',
    'BOOTCONFIG_BYTE_148_UNEXPECTED',
    'APPSBLENV_CRC_INVALID',
    'NO_ROOTFS_1_FOR_AB_ROLLBACK',
    'PINNED_V4_WRITE_TARGET_IS_SELECTED_SLOT_PAIR',
    'BOOTCONFIG_BYTE_148_MEANING_NOT_BOOT_TESTED_ON_ARTHUR',
    'BOOT_SLOT_SWITCH_AND_RECOVERY_NOT_PROVEN',
))

def inspect_image(path: Path) -> dict:
    with tarfile.open(path, mode='r:*') as src:
        names = src.getnames()
        kernels = [x for x in names if x.startswith('sysupgrade-') and x.endswith('/kernel')]
        roots = [x for x in names if x.startswith('sysupgrade-') and x.endswith('/root')]
        if len(kernels) != 1 or len(roots) != 1:
            raise ValueError('Expected exactly one sysupgrade kernel and one root filesystem')
        kernel_member = src.getmember(kernels[0])
        root = src.getmember(roots[0])
        if kernel_member.size > 6 * 1024 * 1024 or root.size > 256 * 1024 * 1024:
            raise ValueError('Sysupgrade member exceeds offline inspection bounds')
        kernel = src.extractfile(kernel_member).read()
        root_magic = src.extractfile(root).read(4)
    if len(kernel) < 40 or kernel[:4] != FIT_MAGIC:
        raise ValueError('Not a valid FIT header')
    internal = struct.unpack_from('>I', kernel, 4)[0]
    if internal != len(kernel):
        raise ValueError('FIT internal size does not match actual bytes')
    for marker in REQUIRED_MARKERS:
        if marker not in kernel:
            raise ValueError(f'FIT missing required marker: {marker.decode()}')
    algorithms = verify_fit(kernel)
    memory_profile = inspect_fit_memory(kernel)
    if root_magic != b'hsqs':
        raise ValueError('Root filesystem is not squashfs')
    return {
        'kernel_bytes': len(kernel),
        'kernel_sha256': hashlib.sha256(kernel).hexdigest(),
        'fits_hlos_6mib': len(kernel) <= LIMIT,
        'kernel_headroom_bytes': LIMIT - len(kernel),
        'rootfs_bytes': root.size,
        'rootfs_is_squashfs': True,
        'fit_subimage_hash_algorithms': algorithms,
        'fit_memory_profile': memory_profile,
        'file': path.name,
        'note': 'FIT subimage digests verified; no signature, boot or recovery verification',
    }

def _merge_evidence(reasons: list, report: dict | None, *, classification: str,
                    allowed: frozenset, prefix: str) -> None:
    if report is None:
        reasons.append(prefix + '_REPORT_MISSING')
    elif (not isinstance(report, dict)
          or report.get('classification') != classification
          or report.get('decision') != 'BLOCKED_WRITE'
          or report.get('write_approved') is not False
          or not isinstance(report.get('blockers'), list)
          or not report['blockers']
          or any(not isinstance(code, str) or code not in allowed
                 for code in report['blockers'])):
        reasons.append(prefix + '_REPORT_INVALID')
    else:
        reasons.extend(prefix + '_' + code
                       for code in sorted(set(report['blockers'])))


def evaluate(layout: dict, image: dict, network_report: dict | None = None,
             hlos_recovery_report: dict | None = None,
             gpt_recovery_report: dict | None = None,
             boot_slot_report: dict | None = None) -> dict:
    reasons=[]
    required_fields=('model','physical_ram_mib','hlos_bytes','rootfs_bytes',
       'has_rootfs_1','backup_hlos_boot_tested','backup_gpt_valid',
       'rescue_tested','v3_ram_boot_tested','v3_full_services_tested',
       'migration_preserves_config_tested','upgrade_path_reviewed')
    for field in required_fields:
        if field not in layout:
            raise ValueError(f'missing inventory field: {field}')
    if layout['model'] != 'JDCloud AX1800_Pro IPQ6018/AP-CP03-C1':
        reasons.append('DEVICE_MISMATCH')
    if layout['physical_ram_mib'] != 1024:
        reasons.append('RAM_NOT_1G')
    if image.get('fit_memory_profile') == 'STATIC_512M_BLOCKED':
        reasons.append('STATIC_512M_DEVICE_TREE_ON_1G_ROUTER')
    elif image.get('fit_memory_profile') != 'STATIC_1G_DECLARED_RUNTIME_UNVERIFIED':
        reasons.append('UNVERIFIED_1G_FIT_MEMORY_MAP')
    if image['kernel_bytes'] > layout['hlos_bytes'] or not image['fits_hlos_6mib']:
        reasons.append('FIT_OVER_HLOS_SIZE')
    if image['rootfs_bytes'] > layout['rootfs_bytes']:
        reasons.append('ROOTFS_OVER_CAPACITY')
    for flag,code in (
        ('has_rootfs_1','NO_SECOND_ROOTFS'),
        ('backup_hlos_boot_tested','BACKUP_HLOS_NOT_BOOT_TESTED'),
        ('backup_gpt_valid','BACKUP_GPT_NOT_VALIDATED'),
        ('rescue_tested','RESCUE_NOT_TESTED'),
        ('v3_ram_boot_tested','V3_1GB_RAM_BOOT_NOT_TESTED'),
        ('v3_full_services_tested','V3_SERVICES_NOT_TESTED'),
        ('migration_preserves_config_tested','CROSS_GENERATION_CONFIG_MIGRATION_NOT_TESTED'),
        ('upgrade_path_reviewed','UPGRADE_WRITE_PATH_NOT_APPROVED'),
    ):
        if layout[flag] is not True:
            reasons.append(code)
    if network_report is None:
        reasons.append('NETWORK_MIGRATION_REPORT_MISSING')
    elif (not isinstance(network_report, dict)
          or network_report.get('classification') != 'READ_ONLY_INVENTORY_NOT_FLASH_APPROVAL'
          or network_report.get('decision') != 'BLOCKED_FIRST_MIGRATION'
          or not isinstance(network_report.get('blockers'), list)
          or not network_report['blockers']
          or any(not isinstance(code, str) or code not in NETWORK_BLOCKERS
                 for code in network_report['blockers'])):
        reasons.append('NETWORK_MIGRATION_REPORT_INVALID')
    else:
        reasons.extend('NETWORK_' + code for code in sorted(set(network_report['blockers'])))
    _merge_evidence(
        reasons, hlos_recovery_report,
        classification='READ_ONLY_RECOVERY_EVIDENCE_NOT_FLASH_APPROVAL',
        allowed=HLOS_RECOVERY_BLOCKERS, prefix='HLOS_RECOVERY_EVIDENCE')
    _merge_evidence(
        reasons, gpt_recovery_report,
        classification='READ_ONLY_GPT_EVIDENCE_NOT_REPAIR_APPROVAL',
        allowed=GPT_RECOVERY_BLOCKERS, prefix='GPT_RECOVERY_EVIDENCE')
    _merge_evidence(
        reasons, boot_slot_report,
        classification='READ_ONLY_BOOT_SLOT_EVIDENCE_NOT_FLASH_APPROVAL',
        allowed=BOOT_SLOT_BLOCKERS, prefix='BOOT_SLOT_EVIDENCE')
    reasons.append('SIGNED_RELEASE_AND_PROVEN_ROLLBACK_NOT_YET_APPROVED')
    return {'offline_image':image, 'write_approved':False,
        'read_only':True,'blockers':reasons,
        'result':'BLOCKED' if reasons else 'PASS',
        'warning':'This tool never flashes devices; it is not a boot or recovery test.'}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True)
    p.add_argument('--sysupgrade',type=Path,required=True)
    p.add_argument('--output',type=Path)
    p.add_argument('--network-report',type=Path,
                   help='Sanitized, read-only legacy network preflight JSON')
    p.add_argument('--hlos-recovery-report',type=Path,
                   help='Read-only output from hlos_recovery_audit.py')
    p.add_argument('--gpt-recovery-report',type=Path,
                   help='Read-only output from gpt_capture_audit.py')
    p.add_argument('--boot-slot-report',type=Path,
                   help='Read-only output from boot_slot_evidence_audit.py')
    args=p.parse_args(argv)
    try:
        network=json.loads(args.network_report.read_text()) if args.network_report else None
        hlos=(json.loads(args.hlos_recovery_report.read_text())
              if args.hlos_recovery_report else None)
        gpt=(json.loads(args.gpt_recovery_report.read_text())
             if args.gpt_recovery_report else None)
        boot_slot=(json.loads(args.boot_slot_report.read_text())
                   if args.boot_slot_report else None)
        doc=evaluate(json.loads(args.inventory.read_text()),inspect_image(args.sysupgrade),
                     network,hlos,gpt,boot_slot)
    except (OSError, ValueError, TypeError, tarfile.TarError, KeyError) as exc:
        print('FAIL: '+str(exc),file=sys.stderr)
        return 3
    body=json.dumps(doc,ensure_ascii=False,indent=2)+'\n'
    if args.output:
        args.output.write_text(body)
    print(body)
    return 2 if not doc['write_approved'] else 0

if __name__=='__main__':
    sys.exit(main())
