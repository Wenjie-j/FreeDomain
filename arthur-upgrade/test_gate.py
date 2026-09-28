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
if __name__=='__main__':
    unittest.main()
