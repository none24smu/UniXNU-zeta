"""Arm2025-09 pp50/52/632 fields and independent LLVM18 old-spelling assembler."""
import importlib.util,re,struct,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import zeta_userland_pauth as p,zeta_userland_code as c

class RegisterLR(unittest.TestCase):
 def test_all_register_fields_and_keys_with_independent_assembler(self):
  cases=[]
  for key in [0,1]:
   for register in range(32):
    # LLVM18 predates Arm's R mnemonic suffix; operand kind distinguishes these.
    mnemonic='auti'+('b' if key else 'a')+'sppc'
    cases.append((mnemonic+(' xzr' if register==31 else ' x'+str(register)),
                  0xdac1901e|(key<<10)|(register<<5),mnemonic+'r',p.NOP))
   for register in range(31):
    mnemonic='reta'+('b' if key else 'a')+'sppc'
    cases.append((mnemonic+' x'+str(register),0xd65f0be0|(key<<10)|register,mnemonic+'r',p.RET))
  result=subprocess.run(['llvm-mc','-triple=aarch64','-mattr=+pauth,+pauth-lr','-show-encoding'],
      input='\n'.join(case[0] for case in cases),text=True,capture_output=True,check=True)
  encoded=re.findall(r'encoding: \[([^]]+)\]',result.stdout)
  self.assertEqual(len(encoded),126)
  for case,encoding in zip(cases,encoded):
   word=int.from_bytes(bytes(int(x,16) for x in encoding.split(',')),'little')
   self.assertEqual(word,case[1]);self.assertEqual(p.lower(word),(case[2],case[3]))
 def test_fixed_bits_and_reserved_return_modifier(self):
  for word in [0xdac1901e,0xdac1941e,0xd65f0be0,0xd65f0fe0]:
   self.assertIsNotNone(p.decode_lr(word))
  for key in [0,0x400]:
   self.assertIsNone(p.decode_lr(0xd65f0bff|key))
   self.assertEqual(p.lower(0xd65f0bff|key)[1],p.RET) # existing old RETAA/B alias
  for bit in range(32):
   if bit in range(5,11):continue # AUT variable Rn and key
   self.assertIsNone(p.decode_lr(0xdac1901e^(1<<bit)))
  for bit in range(32):
   if bit in list(range(5))+[10]:continue # RET variable Rm and key
   self.assertIsNone(p.decode_lr(0xd65f0be0^(1<<bit)))
 def test_register_return_terminates_before_embedded_data(self):
  for word in [0xd65f0be0,0xd65f0ff0,0xd65f0ffe]:
   data=struct.pack('<4I',0xdac1a7fe,word,0xdac10000,0xffffffff)
   insns=c.decode(data,[{'addr':0x1000,'offset':0,'size':len(data)}])
   result=c.walk(insns,data,lambda a,n:a-0x1000,[0x1000],set(),set(),True,{0x1000})
   self.assertEqual(result,({0x1000,0x1004},[],[]))
 def test_aut_register_modifier_does_not_terminate(self):
  data=struct.pack('<3I',0xdac1961e,0xd65f03c0,0xffffffff)
  insns=c.decode(data,[{'addr':0x1000,'offset':0,'size':len(data)}])
  result=c.walk(insns,data,lambda a,n:a-0x1000,[0x1000],set(),set(),True,{0x1000})
  self.assertEqual(result,({0x1000,0x1004},[],[]))

class CandidateMasks(unittest.TestCase):
 def test_every_register_form_is_candidate_without_folding_nearby_data(self):
  import numpy as np
  sys.path.append(str(ROOT.parents[1]/'board/scripts'))
  spec=importlib.util.spec_from_file_location('register_prover',ROOT/'prove-zeta-dyld-cache.py')
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  words=[0xdac1901e|(key<<10)|(rn<<5) for key in range(2) for rn in range(32)]
  words += [0xd65f0be0|(key<<10)|rm for key in range(2) for rm in range(31)]
  self.assertEqual(list(module.pac_candidates(np.array(words+[0xd503201f,0xffffffff],dtype=np.uint32),True)),list(range(126)))

class FixedRegisterLR(unittest.TestCase):
 def test_exact_encodings_against_independent_assembler(self):
  names=['pacia171615','pacib171615','autia171615','autib171615']
  words=[0xdac18bfe,0xdac18ffe,0xdac1bbfe,0xdac1bffe]
  result=subprocess.run(['llvm-mc','-triple=aarch64','-mattr=+pauth,+pauth-lr','-show-encoding'],input='\n'.join(names),text=True,capture_output=True,check=True)
  encoded=re.findall(r'encoding: \[([^]]+)\]',result.stdout)
  self.assertEqual(len(encoded),4)
  for name,word,value in zip(names,words,encoded):
   self.assertEqual(int.from_bytes(bytes(int(x,16) for x in value.split(',')),'little'),word)
   self.assertEqual(p.lower(word),(name,p.NOP))
   for bit in range(10):self.assertIsNone(p.decode_lr(word^(1<<bit)))
 def test_walk_and_candidate_inventory_include_fixed_register_forms(self):
  import numpy as np
  spec=importlib.util.spec_from_file_location('fixed_register_prover',ROOT/'prove-zeta-dyld-cache.py')
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  words=[0xdac18bfe,0xdac18ffe,0xdac1bbfe,0xdac1bffe]
  self.assertEqual(list(module.pac_candidates(np.array(words+[0xdac1bfff,0xffffffff],dtype=np.uint32),True)),list(range(4)))
  raw=struct.pack('<6I',*words,0xd65f03c0,0xffffffff)
  insns=c.decode(raw,[{'addr':0x1000,'offset':0,'size':len(raw)}])
  result=c.walk(insns,raw,lambda a,n:a-0x1000,[0x1000],set(),set(),True,{0x1000})
  self.assertEqual(result,({0x1000,0x1004,0x1008,0x100c,0x1010},[],[]))

if __name__=='__main__':unittest.main()
