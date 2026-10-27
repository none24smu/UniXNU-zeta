"""Exact branch geometry and operand encoding, including refusal boundaries."""
import re
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import zeta_x1_thunks as thunks


class ThunkTests(unittest.TestCase):
    def test_signed_branch_range_edges_and_alignment(self):
        pc=0x10000000
        self.assertEqual(thunks.branch(pc,pc-(1<<27)),0x16000000)
        self.assertEqual(thunks.branch(pc,pc+(1<<27)-4),0x15ffffff)
        self.assertEqual(thunks.branch(pc,pc),0x14000000)
        for source,target in [(pc,pc+(1<<27)),(pc,pc-(1<<27)-4),(pc,pc+1),
                              (pc+1,pc),(0,-4),((1<<64),0),(True,4)]:
            with self.subTest(source=source,target=target),self.assertRaises(ValueError):thunks.branch(source,target)
    def test_non_ctz_and_overflow_or_back_branch_rejected(self):
        for word,original,arena in [(0xdac01c20,0x1000,0x2000),(-1,0x1000,0x2000),
            (0x5ac01820,(1<<64)-4,0x2000),(0x5ac01820,0x1000,(1<<64)-8),
            (0x5ac01820,0x1000,0x1004),(0x5ac01820,0x1000,0xff8)]:
            with self.subTest(word=word,original=original,arena=arena),self.assertRaises(ValueError):thunks.plan_ctz(word,original,arena)
    def test_pc_stages_explicitly_do_not_qualify_signal_delivery(self):
        value=thunks.plan_ctz(0xdac01820,0x1000,0x1100)
        self.assertEqual(value['resume_pc'],0x1004)
        self.assertEqual([x['pc'] for x in value['pc_stages']],[0x1100,0x1104,0x1108])
        self.assertEqual(value['pc_stages'][1]['pending_operation'],'clz-destination')
        self.assertFalse(value['selected_for_conversion'])
        self.assertEqual(value['scratch_registers'],[])
    @unittest.skipUnless(shutil.which('llvm-mc'),'LLVM encoding oracle required')
    def test_all_register_operands_match_llvm_baseline_encoding(self):
        source=[];expected=[]
        for sf in (0,0x80000000):
            prefix='x' if sf else 'w'
            reg=lambda n:prefix+('zr' if n==31 else str(n))
            for rn in range(32):
                for rd in range(32):
                    value=thunks.plan_ctz(sf|0x5ac01800|(rn<<5)|rd,0x1000,0x1100)
                    source.extend([f'rbit {reg(rd)}, {reg(rn)}',f'clz {reg(rd)}, {reg(rd)}'])
                    expected.extend(value['arena_words'][:2])
        result=subprocess.run(['llvm-mc','-triple=aarch64','-mcpu=cortex-a55','--show-encoding'],input='\n'.join(source),text=True,capture_output=True,check=True)
        actual=[]
        for line in result.stdout.splitlines():
            if 'encoding:' in line:
                actual.append(int.from_bytes(bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})',line)),'little'))
        self.assertEqual(actual,expected)


if __name__=='__main__':unittest.main()
