"""Every non-hint PAC form, assembled with llvm-mc, lowered, and decoded back with Capstone."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import zeta_userland_pauth as pauth

# (assembly, expected mnemonic, expected ordinary instruction text)
CASES = [
    ('pacia x1, x2', 'pacia', 'nop'), ('pacib x3, sp', 'pacib', 'nop'), ('pacda x4, x5', 'pacda', 'nop'),
    ('pacdb x6, x7', 'pacdb', 'nop'), ('autia x8, x9', 'autia', 'nop'), ('autib x10, x11', 'autib', 'nop'),
    ('autda x12, x13', 'autda', 'nop'), ('autdb x14, x15', 'autdb', 'nop'), ('paciza x16', 'paciza', 'nop'),
    ('pacizb x17', 'pacizb', 'nop'), ('pacdza x18', 'pacdza', 'nop'), ('pacdzb x19', 'pacdzb', 'nop'),
    ('autiza x20', 'autiza', 'nop'), ('autizb x21', 'autizb', 'nop'), ('autdza x22', 'autdza', 'nop'),
    ('autdzb x23', 'autdzb', 'nop'), ('xpaci x24', 'xpaci', 'nop'), ('xpacd x25', 'xpacd', 'nop'),
    ('pacga x1, x2, x3', 'pacga', 'mov x1, #0'), ('pacga x9, x9, sp', 'pacga', 'mov x9, #0'),
    ('braaz x4', 'braaz', 'br x4'), ('brabz x5', 'brabz', 'br x5'),
    ('blraaz x6', 'blraaz', 'blr x6'), ('blrabz x7', 'blrabz', 'blr x7'),
    ('braa x17, x16', 'braa', 'br x17'), ('brab x8, sp', 'brab', 'br x8'),
    ('blraa x16, x17', 'blraa', 'blr x16'), ('blrab x13, x14', 'blrab', 'blr x13'),
    ('retaa', 'retaa', 'ret'), ('retab', 'retab', 'ret'),
    ('ldraa x1, [x2]', 'ldraa', 'ldr x1, [x2]'), ('ldraa x1, [x2, #4088]', 'ldraa', 'ldr x1, [x2, #0xff8]'),
    ('ldrab x3, [sp, #-256]', 'ldrab', 'ldur x3, [sp, #-0x100]'),
    ('ldraa x5, [x6, #-8]', 'ldraa', 'ldur x5, [x6, #-8]'),
    ('ldraa x7, [x8, #248]!', 'ldraa', 'ldr x7, [x8, #0xf8]!'),
    ('ldrab x9, [x10, #-256]!', 'ldrab', 'ldr x9, [x10, #-0x100]!'),
]
REFUSED = ['eretaa', 'eretab', 'ldraa x1, [x2, #-264]', 'ldraa x1, [x2, #256]!', 'ldrab x1, [x2, #-4096]!']
UNTOUCHED = ['pacibsp', 'autibsp', 'pacia1716', 'xpaclri', 'br x16', 'ret', 'ldr x1, [x2, #8]', 'rev x1, x2',
             'ldadd x1, x2, [x3]', 'ldr x1, [x2, x3]', 'blr x8']


def assemble(lines):
    with tempfile.TemporaryDirectory() as scratch:
        obj, raw = Path(scratch, 'a.o'), Path(scratch, 'a.bin')
        subprocess.run(['llvm-mc', '-triple=aarch64', '-mattr=+pauth,+lse', '-filetype=obj', '-o', obj],
                       input='\n'.join(lines) + '\n', text=True, check=True)
        subprocess.run(['llvm-objcopy', '-O', 'binary', '--only-section=.text', obj, raw], check=True)
        data = raw.read_bytes()
    return list(struct.unpack(f'<{len(data) // 4}I', data))


class LoweringTests(unittest.TestCase):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def text(self, word):
        _, _, mnemonic, operands = next(self.decoder.disasm_lite(struct.pack('<I', word), 0))
        return f'{mnemonic} {operands}'.strip()

    def test_every_form_lowers_to_its_ordinary_equivalent(self):
        for (source, name, expected), word in zip(CASES, assemble([case[0] for case in CASES])):
            with self.subTest(source=source):
                self.assertEqual(self.text(word).split()[0], name)
                mnemonic, ordinary = pauth.lower(word)
                self.assertEqual(mnemonic, name)
                self.assertEqual(self.text(ordinary), expected)

    def test_forms_without_an_exact_lowering_are_refused(self):
        for source, word in zip(REFUSED, assemble(REFUSED)):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    pauth.lower(word)

    def test_other_instructions_are_not_touched(self):
        for source, word in zip(UNTOUCHED, assemble(UNTOUCHED)):
            with self.subTest(source=source):
                self.assertIsNone(pauth.lower(word))

    def test_unallocated_zero_modifier_forms_are_refused(self):
        # paciza with Rn != 31 is unallocated.
        with self.assertRaises(ValueError):
            pauth.lower(0xdac12000 | 2 << 5 | 1)


if __name__ == '__main__':
    unittest.main()
