"""Check the ISA screen against actual LLVM decoding, including known gaps."""
import importlib.util
from pathlib import Path
import sys
import struct
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('isa_audit', SCRIPTS/'audit-zeta-ios27-userland.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class IsaScreenTests(unittest.TestCase):
    def test_baseline_distinguishes_instructions_in_actual_dyld(self):
        supported = {0xd503201f, 0xd65f03c0, 0xf9400028, 0xeb09011f}
        # PACIBSPPC, TCHANGEF, TCHANGEB and ADDPT are not A55 instructions.
        unsupported = {0xdac1a7fe, 0xd5900040, 0xd5940000, 0x9a01212a}
        self.assertEqual(audit.rejected_by_baseline(supported | unsupported), unsupported)

    def test_empty_input(self):
        self.assertEqual(audit.rejected_by_baseline([]), set())

    def test_permission_transitions_decode_as_code_but_are_not_lowered(self):
        data=struct.pack('<4I',0xd5900040,0xd5940000,0xd65f03c0,0xdac10000)
        insns=audit.code.decode(data,[{'offset':0,'size':len(data),'addr':0x1000}])
        self.assertEqual(insns[0x1000],('tchangef','x0, #2'))
        self.assertEqual(insns[0x1004],('tchangeb','x0, #0'))
        proven,tables,anomalies=audit.code.walk(
            insns,data,lambda va,n:va-0x1000,[0x1000],set(),set(),True,{0x1000})
        self.assertEqual(proven,{0x1000,0x1004,0x1008})
        self.assertEqual((tables,anomalies),([],[]))
        for word in [0xd5900040,0xd5940000]:
            self.assertIsNone(audit.pauth.lower(word))
        self.assertEqual(audit.rejected_by_baseline([0xd5900040,0xd5940000]),
                         {0xd5900040,0xd5940000})


if __name__ == '__main__':
    unittest.main()
