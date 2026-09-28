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
        self.assertIn('NO_SECOND_ROOTFS',report['blockers'])
        self.assertIn('RESCUE_NOT_TESTED',report['blockers'])
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
if __name__=='__main__':
    unittest.main()
