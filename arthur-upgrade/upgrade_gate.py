#!/usr/bin/env python3
"""Offline read-only compatibility gate. Never writes router flash or boot vars."""
from __future__ import annotations
import argparse, hashlib, json, struct, sys, tarfile
from pathlib import Path

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

def inspect_image(path: Path) -> dict:
    with tarfile.open(path, mode='r:*') as src:
        names = src.getnames()
        kernels = [x for x in names if x.startswith('sysupgrade-') and x.endswith('/kernel')]
        roots = [x for x in names if x.startswith('sysupgrade-') and x.endswith('/root')]
        if len(kernels) != 1 or len(roots) != 1:
            raise ValueError('Expected exactly one sysupgrade kernel and one root filesystem')
        kernel = src.extractfile(kernels[0]).read()
        root = src.getmember(roots[0])
    if len(kernel) < 40 or kernel[:4] != FIT_MAGIC:
        raise ValueError('Not a valid FIT header')
    internal = struct.unpack_from('>I', kernel, 4)[0]
    if internal != len(kernel):
        raise ValueError('FIT internal size does not match actual bytes')
    for marker in REQUIRED_MARKERS:
        if marker not in kernel:
            raise ValueError(f'FIT missing required marker: {marker.decode()}')
    return {
        'kernel_bytes': len(kernel),
        'kernel_sha256': hashlib.sha256(kernel).hexdigest(),
        'fits_hlos_6mib': len(kernel) <= LIMIT,
        'kernel_headroom_bytes': LIMIT - len(kernel),
        'rootfs_bytes': root.size,
        'file': path.name,
        'note': 'Markers and size only; FIT cryptographic subimage verification is separate',
    }

def evaluate(layout: dict, image: dict, network_report: dict | None = None) -> dict:
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
    args=p.parse_args(argv)
    try:
        network=json.loads(args.network_report.read_text()) if args.network_report else None
        doc=evaluate(json.loads(args.inventory.read_text()),inspect_image(args.sysupgrade),network)
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
