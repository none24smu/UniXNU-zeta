"""Check operand rejection, architecture limits and all real split references."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import zeta_prelink_layout as L
import zeta_prelink_relocate as R


class InstructionTests(unittest.TestCase):
    def test_page_and_branch_limits_and_original_operand_checks(self):
        self.assertEqual(R.instruction(5, 0x90000008, 0x1000, 0x1000, 0x8000, 0x9000), 0xb0000008)
        self.assertEqual(R.instruction(6, 0x91000408, 0x1000, 1, 0x8000, 0x33), 0x9100cc08)
        self.assertEqual(R.instruction(7, 0x94000002, 0x1000, 0x1008, 0x8000, 0x8010), 0x94000004)
        for args in ((5, 0x90000008, 0x1000, 0x2000, 0x8000, 0x9000),
                     (6, 0xf9400408, 0x1000, 8, 0x8000, 3),
                     (7, 0x94000002, 0x1000, 0x1008, 0x8000, 0x8000 + (1 << 27)),
                     (5, 0x90000008, 0x1000, 0x1000, 0, 1 << 32)):
            with self.assertRaises(ValueError):
                R.instruction(*args)


@unittest.skipUnless(os.environ.get('ZETA_PRELINK_FIXTURE_ROOT'), 'supply pinned artifacts')
class ActualRelocationTests(unittest.TestCase):
    def test_all_six_real_reference_streams_have_checked_rewrites(self):
        def load(name, file):
            spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
            value = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(value)
            return value
        A, P = load('strict_macho', 'audit-zeta-apfs.py'), load('pauth', 'audit-zeta-apfs-pauth.py')
        root = Path(os.environ['ZETA_PRELINK_FIXTURE_ROOT'])
        path = root / 'work/apfs-abi-ci-artifact/unixnu-zeta_apfs_abi_defconfig/zeta/kernel/mach.development.bcm2837.unstripped.noctf'
        native = A.MachO(path.read_bytes(), path)
        modules = {p.stem: A.MachO(p.read_bytes(), p, candidate=True)
                   for p in (root / 'work/apfs-stage6/closure-pauth').glob('*.macho')}
        layout = L.plan(native, modules)
        closure = json.loads((root / 'work/apfs-stage6/closure-profile-built.json').read_text())
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        from capstone.arm64_const import ARM64_OP_MEM
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        total = 0
        for identifier, image in modules.items():
            split = json.loads((root / 'work/apfs-stage6/split-info-v2' / (identifier + '.json')).read_text())
            pauth = P.audit(Path(image.identity['path']))
            result = R.module_plan(image, identifier, layout, split, pauth, closure['module_reports'][identifier])
            proposed = {e['fileoff']: e for e in result['proposed_edits']}
            # Independently decode every rewritten code operand with Capstone.
            # This catches writer bit/scale/sign errors across all real inputs.
            for row in split['references']:
                if row['kind'] not in (5, 6, 7):
                    continue
                pc = L.translate(layout, identifier, row['source_va'], 4)
                target = L.translate(layout, identifier, row['target_va'])
                instructions = list(decoder.disasm(bytes.fromhex(proposed[row['source_fileoff']]['new']), pc))
                self.assertEqual(len(instructions), 1)
                insn = instructions[0]
                if row['kind'] == 5:
                    self.assertEqual(insn.mnemonic, 'adrp')
                    self.assertEqual(insn.operands[1].imm & L.U64, target & ~4095)
                elif row['kind'] == 7:
                    self.assertIn(insn.mnemonic, ('b', 'bl'))
                    self.assertEqual(insn.operands[0].imm & L.U64, target)
                else:
                    memories = [op for op in insn.operands if op.type == ARM64_OP_MEM]
                    offset = memories[0].mem.disp if memories else insn.operands[2].imm
                    self.assertEqual(offset, target & 4095)
            total += sum(count for name, count in result['counts'].items() if name.startswith('split:'))
            self.assertFalse(result['driver_loadable'])
            if identifier == 'com.apple.filesystems.apfs':
                self.assertEqual(len(result['unresolved']), 1)  # CSR is absent in this first profile.
        self.assertEqual(total, 63403)


if __name__ == '__main__':
    unittest.main(verbosity=2)
