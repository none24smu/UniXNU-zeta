"""PAuth_LR conversion against LLVM's independent instruction assembler."""
import importlib.util,re,struct,subprocess,sys,unittest
from pathlib import Path
SCRIPTS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SCRIPTS))
import zeta_userland_pauth as p
import zeta_userland_code as c

class PAuthLRTests(unittest.TestCase):
    def test_all_immediate_bits_and_keys(self):
        for imm in range(65536):
            for key in [0,0x200000]:
                ret=0x5500001f|key|(imm<<5);aut=0xf380001f|key|(imm<<5)
                self.assertEqual(p.lower(ret)[1],p.RET)
                self.assertEqual(p.lower(aut)[1],p.NOP)
                self.assertEqual(p.decode_lr(ret)[1],'#'+str(-imm*4))
    def test_independent_llvm_assembler(self):
        text='paciasppc\npacibsppc\n'
        for mnemonic in ['autiasppc','autibsppc','retaasppc','retabsppc']:
            text+=''.join(f'{mnemonic} #{offset}\n' for offset in [0,-4,-256,-262140])
        result=subprocess.run(['llvm-mc','-triple=aarch64','-mattr=+pauth,+pauth-lr','-show-encoding'],input=text,text=True,capture_output=True,check=True)
        encoded=re.findall(r'encoding: \[([^]]+)\]',result.stdout)
        self.assertEqual(len(encoded),18)
        for original,encoding in zip(text.splitlines(),encoded):
            word=int.from_bytes(bytes(int(x,16) for x in encoding.split(',')),'little')
            self.assertEqual(p.lower(word)[0],original.split()[0])
            self.assertEqual(p.lower(word)[1],p.RET if original.startswith('ret') else p.NOP)
    def test_return_ends_walk_before_embedded_data(self):
        data=struct.pack('<4I',0xdac1a3fe,0x5500003f,0xdac10000,0xffffffff)
        section={'offset':0,'size':len(data),'addr':0x1000}
        insns=c.decode(data,[section]);self.assertEqual(insns[0x1004][0],'retaasppc')
        code,tables,anomalies=c.walk(insns,data,lambda va,n:va-0x1000,[0x1000],set(),set(),True,{0x1000})
        self.assertEqual(code,{0x1000,0x1004});self.assertEqual(tables,[]);self.assertEqual(anomalies,[])
    def test_neighbour_encodings_are_not_lr(self):
        for word in [0xdac1a3ff,0xdac1a3de,0x5500001e,0x5540001f,0xf380001e,0xf3c0001f,0xd503201f]:
            self.assertIsNone(p.decode_lr(word))
    def test_pacm_stays_hint(self):
        self.assertIsNone(p.lower(0xd50324ff))

if __name__=='__main__':unittest.main()
