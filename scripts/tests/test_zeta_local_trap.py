import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));import zeta_userland_code as code

class TrapProof(unittest.TestCase):
 def test_only_metadata_rooted_straightline_trap(self):
  ins={0x1000:('pacibsppc',''),0x1004:('bl','#0x2000'),0x1008:('brk','#1')}
  self.assertEqual(code.straightline_trap_roots(ins,{0x1000},{0x1000}),{0x1000})
  self.assertEqual(code.straightline_trap_roots(ins,set(),{0x1000}),set())
  self.assertEqual(code.straightline_trap_roots(ins,{0x1000},set()),set())
  self.assertEqual(code.straightline_trap_roots(ins,{0x1000},{0x1000,0x1008}),set())
 def test_no_branch_return_or_implicit_trap_shortcuts(self):
  for instruction in [('b','#0x1008'),('b.eq','#0x1008'),('cbz','x0, #0x1008'),('br','x0'),('ret',''),('retabsppcr','x16'),('udf','#0'),('brk','#2'),('.byte','0')]:
   with self.subTest(instruction=instruction):
    ins={0x1000:('pacibsppc',''),0x1004:instruction,0x1008:('brk','#1')}
    self.assertEqual(code.straightline_trap_roots(ins,{0x1000},{0x1000}),set())
 def test_missing_words_and_bounded_size_reject(self):
  self.assertEqual(code.straightline_trap_roots({0x1000:('pacibsppc',''),0x1008:('brk','#1')},{0x1000},{0x1000}),set())
  ins={0x1000:('pacibsppc',''),**{0x1000+i*4:('nop','') for i in range(1,32)},0x1080:('brk','#1')}
  self.assertEqual(code.straightline_trap_roots(ins,{0x1000},{0x1000}),set())
 def test_noreturn_inference_closes_wrapper_but_arbitrary_call_stays_rejected(self):
  ins={0x1000:('pacibsppc',''),0x1004:('nop',''),0x1008:('brk','#1'),0x1010:('pacibsppc',''),0x1014:('bl','#0x1000')}
  result=code.prove_roots(ins,b'',lambda a,n:0,{0x1000,0x1010},set(),{0x1000,0x1010},set())
  self.assertEqual(result[4],[])
  self.assertEqual(set(result[1]),set(ins))
  ins[0x1008]=('ret','')
  result=code.prove_roots(ins,b'',lambda a,n:0,{0x1000,0x1010},set(),{0x1000,0x1010},set())
  self.assertEqual(result[4],[{'kind':'leaves_instruction_sections','address':'0x1018'}])

if __name__=='__main__':unittest.main()
