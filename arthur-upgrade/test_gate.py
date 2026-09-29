#!/usr/bin/env python3
import json, unittest
from pathlib import Path
from upgrade_gate import evaluate

INV = Path(__file__).with_name('inventory-arthur-1gb-v3.json')

class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.layout=json.loads(INV.read_text())
        self.image={'kernel_bytes':5674292,'fits_hlos_6mib':True,'rootfs_bytes':14880768}
    def test_known_router_must_block(self):
        report=evaluate(self.layout,self.image)
        self.assertFalse(report['write_approved'])
        self.assertIn('UNVERIFIED_1G_FIT_MEMORY_MAP',report['blockers'])
        self.assertIn('NO_SECOND_ROOTFS',report['blockers'])
        self.assertIn('RESCUE_NOT_TESTED',report['blockers'])
        self.image['fit_memory_profile']='STATIC_512M_BLOCKED'
        self.assertIn('STATIC_512M_DEVICE_TREE_ON_1G_ROUTER',
                      evaluate(self.layout,self.image)['blockers'])
    def test_wrong_device_must_block(self):
        self.layout['model']='WRONG'
        self.assertIn('DEVICE_MISMATCH',evaluate(self.layout,self.image)['blockers'])
    def test_kernel_over_limit_must_block(self):
        self.image['kernel_bytes']=7*1024*1024
        self.image['fits_hlos_6mib']=False
        self.assertIn('FIT_OVER_HLOS_SIZE',evaluate(self.layout,self.image)['blockers'])
    def test_no_unreviewed_flash_even_with_flags(self):
        for flag in ('has_rootfs_1','backup_hlos_boot_tested',
            'backup_gpt_valid','rescue_tested','v3_ram_boot_tested',
            'v3_full_services_tested','migration_preserves_config_tested',
            'upgrade_path_reviewed'):
            self.layout[flag]=True
        self.assertFalse(evaluate(self.layout,self.image)['write_approved'])
        self.assertIn('SIGNED_RELEASE_AND_PROVEN_ROLLBACK_NOT_YET_APPROVED',
                      evaluate(self.layout,self.image)['blockers'])
    def test_network_report_is_combined_without_exposing_device_values(self):
        network={'classification':'READ_ONLY_INVENTORY_NOT_FLASH_APPROVAL',
                 'decision':'BLOCKED_FIRST_MIGRATION',
                 'blockers':['PHYSICAL_ETHERNET_MAPPING_UNVERIFIED'],
                 'interfaces':{'wan':{'secret':'DO_NOT_PRINT'}}}
        report=evaluate(self.layout,self.image,network)
        self.assertIn('NETWORK_PHYSICAL_ETHERNET_MAPPING_UNVERIFIED',report['blockers'])
        self.assertNotIn('DO_NOT_PRINT',json.dumps(report))
    def test_missing_or_spoofed_network_report_fails_closed(self):
        self.assertIn('NETWORK_MIGRATION_REPORT_MISSING',
                      evaluate(self.layout,self.image)['blockers'])
        for invalid in ({'classification':'READ_ONLY_INVENTORY_NOT_FLASH_APPROVAL',
                         'decision':'PASS','blockers':['PHYSICAL_ETHERNET_MAPPING_UNVERIFIED']},
                        {'classification':'READ_ONLY_INVENTORY_NOT_FLASH_APPROVAL',
                         'decision':'BLOCKED_FIRST_MIGRATION',
                         'blockers':['PASSWORD=secret']}, []):
            report=evaluate(self.layout,self.image,invalid)
            self.assertIn('NETWORK_MIGRATION_REPORT_INVALID',report['blockers'])
            self.assertNotIn('secret',json.dumps(report))
    def test_recovery_evidence_is_merged_without_copying_private_fields(self):
        hlos={'classification':'READ_ONLY_RECOVERY_EVIDENCE_NOT_FLASH_APPROVAL',
              'decision':'BLOCKED_WRITE','write_approved':False,
              'blockers':['HLOS_1_NO_VERIFIED_FIT_AT_OFFSET_ZERO'],
              'partitions':{'private':'DO_NOT_COPY'}}
        gpt={'classification':'READ_ONLY_GPT_EVIDENCE_NOT_REPAIR_APPROVAL',
             'decision':'BLOCKED_WRITE','write_approved':False,
             'blockers':['TERMINAL_BACKUP_GPT_HEADER_MISSING'],
             'capture':{'private':'DO_NOT_COPY'}}
        report=evaluate(self.layout,self.image,None,hlos,gpt)
        self.assertIn(
            'HLOS_RECOVERY_EVIDENCE_HLOS_1_NO_VERIFIED_FIT_AT_OFFSET_ZERO',
            report['blockers'])
        self.assertIn(
            'GPT_RECOVERY_EVIDENCE_TERMINAL_BACKUP_GPT_HEADER_MISSING',
            report['blockers'])
        self.assertNotIn('DO_NOT_COPY',json.dumps(report))
    def test_missing_or_spoofed_recovery_evidence_fails_closed(self):
        report=evaluate(self.layout,self.image)
        self.assertIn('HLOS_RECOVERY_EVIDENCE_REPORT_MISSING',report['blockers'])
        self.assertIn('GPT_RECOVERY_EVIDENCE_REPORT_MISSING',report['blockers'])
        self.assertIn('BOOT_SLOT_EVIDENCE_REPORT_MISSING',report['blockers'])
        spoofed={'classification':'READ_ONLY_RECOVERY_EVIDENCE_NOT_FLASH_APPROVAL',
                 'decision':'PASS','write_approved':True,
                 'blockers':['PASSWORD=secret']}
        report=evaluate(self.layout,self.image,None,spoofed,spoofed)
        self.assertIn('HLOS_RECOVERY_EVIDENCE_REPORT_INVALID',report['blockers'])
        self.assertIn('GPT_RECOVERY_EVIDENCE_REPORT_INVALID',report['blockers'])
        self.assertNotIn('secret',json.dumps(report))
    def test_boot_slot_evidence_is_allowlisted_and_redacted(self):
        boot={'classification':'READ_ONLY_BOOT_SLOT_EVIDENCE_NOT_FLASH_APPROVAL',
              'decision':'BLOCKED_WRITE','write_approved':False,
              'blockers':['PINNED_V4_WRITE_TARGET_IS_SELECTED_SLOT_PAIR'],
              'raw':{'password':'DO_NOT_COPY'}}
        report=evaluate(self.layout,self.image,None,None,None,boot)
        self.assertIn(
            'BOOT_SLOT_EVIDENCE_PINNED_V4_WRITE_TARGET_IS_SELECTED_SLOT_PAIR',
            report['blockers'])
        self.assertNotIn('DO_NOT_COPY',json.dumps(report))
if __name__=='__main__':
    unittest.main()
