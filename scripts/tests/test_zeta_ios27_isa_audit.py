"""Check the ISA screen against actual LLVM decoding, including known gaps."""
import importlib.util
from pathlib import Path
import sys
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


if __name__ == '__main__':
    unittest.main()
