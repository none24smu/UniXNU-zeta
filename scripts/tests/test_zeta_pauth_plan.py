"""Independent instruction decoding and fail-closed PAuth-plan checks."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from zeta_pauth_plan import lower_word, plan_section
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


def decoder():
    result = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    result.skipdata = True
    return result


class EncodingTests(unittest.TestCase):
    def test_operand_and_link_encodings_match_llvm_assembler(self):
        import re
        for reg in (0, 8, 16, 29, 30):
            for original, wanted in ((f'braa x{reg}, x17', f'br x{reg}'),
                                     (f'blraa x{reg}, x17', f'blr x{reg}'),
                                     (f'blraaz x{reg}', f'blr x{reg}')):
                with self.subTest(original=original):
                    run = subprocess.run(['llvm-mc', '-triple=aarch64', '-mattr=+pauth', '-show-encoding'],
                                         input=original + '\n' + wanted + '\n', text=True,
                                         capture_output=True, check=True)
                    encodings = re.findall(r'encoding: \[([^]]+)\]', run.stdout)
                    words = [int.from_bytes(bytes(int(v.strip(), 16) for v in row.split(',')), 'little')
                             for row in encodings]
                    self.assertEqual(len(words), 2)
                    self.assertEqual(lower_word(words[0])[1], words[1])
            run = subprocess.run(['llvm-mc', '-triple=aarch64', '-mattr=+pauth', '-show-encoding'],
                                 input=f'autiza x{reg}\n', text=True, capture_output=True, check=True)
            encoding = re.search(r'encoding: \[([^]]+)\]', run.stdout).group(1)
            word = int.from_bytes(bytes(int(v.strip(), 16) for v in encoding.split(',')), 'little')
            self.assertEqual(lower_word(word), ('autiza', 0xd503201f))

    def test_new_pauth_families_are_rejected(self):
        for word in (0x9ac93008, 0xf8200528, 0xd65f0bff, 0xd73f0d09):
            with self.subTest(word=hex(word)):
                with self.assertRaisesRegex(ValueError, 'unsupported|incomplete'):
                    plan_section(struct.pack('<I', word), 0x1000, 0, decoder())

    def test_truncated_or_undecodable_code_is_rejected(self):
        for code in (b'\0', b'\xff' * 4):
            with self.assertRaisesRegex(ValueError, 'unaligned|incomplete'):
                plan_section(code, 0x1000, 0, decoder())

    def test_unrelated_instructions_are_unchanged_in_plan(self):
        self.assertEqual(plan_section(struct.pack('<II', 0xd503201f, 0xd65f03c0),
                                      0x1000, 0, decoder()), [])

    def test_auth_branch_zero_target_is_rejected(self):
        for word in (0xd71f0be0, 0xd73f0be0, 0xd63f0bff):
            with self.assertRaisesRegex(ValueError, 'zero-register branch'):
                lower_word(word)


if __name__ == '__main__':
    unittest.main()
