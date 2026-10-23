"""Code-proof unit cases and an independent check of rewritten userland images.

The synthetic cases assemble small instruction streams with llvm-mc. The
actual-artifact case reads ZETA_USERLAND_REWRITE_DIR (rewritten images next
to their <name>.json reports) and resolves each report's input path against
ZETA_USERLAND_REWRITE_ROOT. It never imports the rewriter or the code proof:
it diffs the images, decodes every changed word with Capstone, and hashes
the code pages and CodeDirectory itself. ZETA_USERLAND_TREE_REPORT runs the same
check on every image of a rewrite-zeta-userland-tree report.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import numpy as np

BASE = 0x1000
# A hardened dispatch whose last case calls a noreturn function placed
# directly before the jump table, then a data atom holding a pacda word.
DISPATCH = '''
    pacibsp
    cmp x16, #2
    csel x16, x16, xzr, ls
    adrp x17, #0
    add x17, x17, #0x40
    ldrsw x16, [x17, x16, lsl #2]
    adr x17, #0xc
    add x16, x17, x16
    br x16
    autibsp
    retab
    paciza x0
    retab
    nop
    nop
    bl #0x14
    .word 0, 8, 0x10
    pacda x1, x2
    brk #1
'''
STARTS = {0x1000, 0x1040, 0x104c, 0x1050}


def assemble(source):
    with tempfile.TemporaryDirectory() as scratch:
        obj, raw = Path(scratch, 'a.o'), Path(scratch, 'a.bin')
        subprocess.run(['llvm-mc', '-triple=aarch64', '-mattr=+pauth', '-filetype=obj', '-o', obj],
                       input=source, text=True, check=True)
        subprocess.run(['llvm-objcopy', '-O', 'binary', '--only-section=.text', obj, raw], check=True)
        return raw.read_bytes()


class CodeProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import zeta_userland_code
        cls.c = zeta_userland_code
        cls.data = assemble(DISPATCH)
        cls.insns = cls.c.decode(cls.data, [dict(offset=0, size=len(cls.data), addr=BASE)])
        cls.va_to_off = staticmethod(lambda address, length: address - BASE)

    def walk(self, roots, strict=False, boundaries=STARTS, code=frozenset(), data_words=frozenset()):
        return self.c.walk(self.insns, self.data, self.va_to_off, roots, set(code), set(data_words),
                           strict, boundaries)

    def test_dispatch_decodes_exact_table_and_targets(self):
        table = self.c.jump_table(self.insns, self.data, self.va_to_off, 0x1020)
        self.assertEqual((table['table'], table['entries'], table['anchor']), (0x1040, 3, 0x1024))
        self.assertEqual(table['targets'], [0x1024, 0x102c, 0x1034])

    def test_walk_stops_at_the_atom_after_a_noreturn_call(self):
        code, tables, anomalies = self.walk([0x1000])
        self.assertEqual(sorted(code), list(range(0x1000, 0x1040, 4)) + [0x1050])
        self.assertFalse(code & self.c.table_words(tables))
        self.assertEqual(anomalies, [])

    def test_without_atom_boundaries_the_walk_runs_into_the_table(self):
        code, tables, _ = self.walk([0x1000], boundaries=set())
        self.assertTrue(code & self.c.table_words(tables))

    def test_tentative_walks_reject_tables_and_unterminated_data(self):
        self.assertIsNone(self.walk([0x1040], strict=True))
        # pacda decodes, but it runs into the next start without a call.
        self.assertIsNone(self.walk([0x104c], strict=True))
        self.assertEqual(self.walk([0x1050], strict=True)[0], {0x1050})

    def test_materialized_addresses_pair_adrp_with_add(self):
        code, _, _ = self.walk([0x1000])
        self.assertEqual(self.c.materialized(self.insns, code), {0x1040, 0x1024})

    def test_unwind_regular_and_compressed_pages(self):
        common = [0x04000000]
        index = struct.pack('<3I', 0x1000, 68, 0) + struct.pack('<3I', 0x2000, 92, 0) + struct.pack('<3I', 0x3000, 0, 0)
        header = struct.pack('<7I', 1, 28, len(common), 0, 0, 32, 3) + struct.pack('<I', *common)
        regular = struct.pack('<IHH', 2, 8, 2) + struct.pack('<4I', 0x1000, 0x02000000, 0x1040, 0)
        # Compressed entries: encoding index in the top byte, offset from the page's function.
        compressed = (struct.pack('<IHHHH', 3, 12, 2, 20, 1) + struct.pack('<2I', 0x000000, 0x01000010)
                      + struct.pack('<I', 0x04000007))
        blob = header + index
        self.assertEqual(len(blob), 68)
        blob += regular
        self.assertEqual(len(blob), 92)
        blob += compressed
        info = dict(segments=[dict(name='__TEXT', vmaddr=0, sections=[
            dict(name='__unwind_info', offset=0, size=len(blob))])])
        self.assertEqual(self.c.unwind_encodings(blob, info, 0x100000000), {
            0x100001000: 0x02000000, 0x100001040: 0, 0x100002000: 0x04000000, 0x100002010: 0x04000007})

    def test_chained_rebase_targets_skip_binds(self):
        data = bytearray(0x228)
        struct.pack_into('<IIII', data, 16, 1, 16, 0, 0)
        struct.pack_into('<IIII', data, 32, 0x80000034, 16, 0x100, 0x60)
        struct.pack_into('<II', data, 0x100, 0, 0x20)
        struct.pack_into('<III', data, 0x120, 2, 0, 12)
        struct.pack_into('<IHHQIHH', data, 0x12c, 24, 0x4000, 12, 0x4000, 0, 1, 0x10)
        struct.pack_into('<3Q', data, 0x210, 1 << 51 | 0x1234, 1 << 63 | 1 << 51 | 0x2000, 1 << 62 | 7)
        info = dict(segments=[dict(name='__TEXT', vmaddr=0x100000000, fileoff=0),
                              dict(name='__DATA', vmaddr=0x100004000, fileoff=0x200)])
        self.assertEqual(self.c.pointer_targets(bytes(data), info), {0x100001234, 0x100002000})

    def test_arm64e_chains_rebase_to_an_absolute_address(self):
        # DYLD_CHAINED_PTR_ARM64E (format 1): plain rebases hold the address, auth rebases an offset.
        data = bytearray(0x228)
        struct.pack_into('<IIII', data, 16, 1, 16, 0, 0)
        struct.pack_into('<IIII', data, 32, 0x80000034, 16, 0x100, 0x60)
        struct.pack_into('<II', data, 0x100, 0, 0x20)
        struct.pack_into('<III', data, 0x120, 2, 0, 12)
        struct.pack_into('<IHHQIHH', data, 0x12c, 24, 0x4000, 1, 0x4000, 0, 1, 0x10)
        struct.pack_into('<3Q', data, 0x210, 1 << 51 | 0x100001234, 1 << 63 | 1 << 51 | 0x2000, 1 << 62 | 7)
        info = dict(segments=[dict(name='__TEXT', vmaddr=0x100000000, fileoff=0),
                              dict(name='__DATA', vmaddr=0x100004000, fileoff=0x200)])
        self.assertEqual(self.c.pointer_targets(bytes(data), info), {0x100001234, 0x100002000})
        struct.pack_into('<H', data, 0x132, 2)   # DYLD_CHAINED_PTR_64 is not arm64e
        with self.assertRaises(ValueError):
            self.c.pointer_targets(bytes(data), info)

    def test_strict_walks_accept_the_trap_after_a_noreturn_call(self):
        data = assemble('bl #8\nudf #0\nret\nudf #0\n')
        insns = self.c.decode(data, [dict(offset=0, size=len(data), addr=BASE)])
        walk = lambda root: self.c.walk(insns, data, None, [root], set(), set(), True, set())
        self.assertEqual(walk(BASE)[0], {BASE, BASE + 8})
        self.assertIsNone(walk(BASE + 12))

    def test_external_code_ends_a_path_without_failing_it(self):
        class External(set):
            reached = set()
        data = assemble('bl #0x100\nret\n')
        insns = self.c.decode(data, [dict(offset=0, size=len(data), addr=BASE)])
        external = External({BASE + 0x100})
        found = self.c.walk(insns, data, None, [BASE], set(), set(), True, set(), external)
        self.assertEqual(found[0], {BASE, BASE + 4})
        self.assertEqual(external.reached, {BASE + 0x100})

    def test_oracle_steps_over_amx_and_sme_but_not_branches(self):
        sme = assemble('.arch_extension sme2\nfmla za.s[w8, 0, vgx4], {z0.s-z3.s}, z4.s\n')
        amx = struct.pack('<I', 0x00201000 | 17 << 5)
        retab = assemble('retab\n')
        data = sme + amx + retab
        section = [dict(offset=0, size=len(data), addr=BASE)]
        self.assertIsNone(self.c.walk(self.c.decode(data, section), data, None, [BASE], set(), set(), True, set()))
        insns = self.c.decode(data, section, self.c.llvm_oracle)
        self.assertEqual(insns[BASE][0], 'fmla')
        self.assertEqual(insns[BASE + 4], ('amx', '17, 0'))
        found = self.c.walk(insns, data, None, [BASE], set(), set(), True, set())
        self.assertEqual(found[0], {BASE, BASE + 4, BASE + 8})
        # Branches, traps and returns are never given to a walk as straight-line words.
        self.assertEqual(self.c.llvm_oracle({0x54000050, 0xd65f0fff, 0xd4200020, 0}), {})

    def test_stack_cleanup_after_a_noreturn_call_may_reach_the_next_atom(self):
        # bl to the ret at 0x101c; its cleanup runs into the atom at 0x1008. 0x1010 runs into 0x1014.
        data = assemble('bl #0x1c\nadd sp, sp, #0x10\npacibsp\nret\nmov x0, x1\npacibsp\nret\nret\n')
        insns = self.c.decode(data, [dict(offset=0, size=len(data), addr=BASE)])
        found = self.c.walk(insns, data, None, [BASE], set(), set(), True, {BASE + 8})
        self.assertEqual(found[0], {BASE, BASE + 4, BASE + 0x1c})
        self.assertIsNone(self.c.walk(insns, data, None, [BASE + 16], set(), set(), True, {BASE + 20}))

    def test_falling_into_proven_code_and_retrying_rejected_roots(self):
        # Root 0x1000 falls into the start at 0x1008, which only a later root proves.
        data = assemble('mov x0, x1\npacia x0, x1\nmov x2, x3\nret\n')
        insns = self.c.decode(data, [dict(offset=0, size=len(data), addr=BASE)])
        self.assertIsNone(self.c.walk(insns, data, None, [BASE], set(), set(), True, {BASE + 8}))
        proven = dict.fromkeys([BASE + 8, BASE + 12], 'start')
        self.assertEqual(self.c.walk(insns, data, None, [BASE], proven, set(), True, {BASE + 8})[0], {BASE, BASE + 4})
        _, code, _, _, _, roots = self.c.prove_roots(insns, data, None, set(), {BASE, BASE + 8}, {BASE, BASE + 8},
                                                     set())
        self.assertEqual(set(code), {BASE, BASE + 4, BASE + 8, BASE + 12})
        self.assertEqual((roots['start_accepted'], roots['rejected']), (2, []))

    def test_gap_grade_proves_dead_epilogues_but_not_tables(self):
        # Atom 0x1000: loop with a trap exit and a dead epilogue. Atom 0x101c: a ret, then table words.
        # Atom 0x1028: a ret, then a gap that would run into the data atom 0x1030.
        data = assemble('pacibsp\ncbz x0, #8\nb #-4\nbrk #0\nmov x0, #7\nretab\nnop\n'
                        'ret\n.word 0x10, 0x20\n'
                        'ret\nmov x1, x2\n.word 0x30\n')
        section = [dict(offset=0, size=len(data), addr=BASE)]
        insns = self.c.decode(data, section)
        strong = {BASE, BASE + 0x1c, BASE + 0x28}
        starts = strong | {BASE + 0x30}
        _, code, _, _, _, roots = self.c.prove_roots(insns, data, None, strong, set(), starts, set())
        self.assertNotIn(BASE + 0x14, code)
        self.assertNotIn('gap_accepted', roots)
        _, code, _, _, _, roots = self.c.prove_roots(insns, data, None, strong, set(), starts, set(), gaps=True)
        self.assertEqual((code[BASE + 0x10], code[BASE + 0x14], code[BASE + 0x18]), ('gap',) * 3)
        self.assertNotIn(BASE + 0x20, code)
        self.assertNotIn(BASE + 0x2c, code)
        self.assertEqual(roots['gap_accepted'], 2)   # the epilogue and the nop padding after it

    def test_hinted_conditional_branch_is_followed(self):
        data = struct.pack('<I', 0x54000050) + assemble('ret\nret\n')   # bc.eq #+8
        insns = self.c.decode(data, [dict(offset=0, size=len(data), addr=BASE)])
        found = self.c.walk(insns, data, None, [BASE], set(), set(), True, set())
        self.assertEqual(found[0], {BASE, BASE + 4, BASE + 8})

    def test_lsda_index_and_call_site_table(self):
        # __unwind_info with two first-level entries and one LSDA pair (function 0x100, LSDA 0x40).
        blob = struct.pack('<7I', 1, 28, 0, 0, 0, 28, 2) + struct.pack('<3I', 0x100, 0, 52)
        blob += struct.pack('<3I', 0x200, 0, 60) + struct.pack('<II', 0x100, 0x40)
        self.assertEqual(len(blob), 60)
        self.assertEqual(self.c.unwind_lsdas(blob, 0x1000), {0x1100: 0x1040})
        # LPStart omitted, type table at uleb 0x10, 8 bytes of uleb128 call sites:
        # (0x00, 0x10, no pad, no action) and (0x10, 0x08, pad 0x30, action 1).
        lsda = bytes([0xff, 0x9b, 0x10, 0x01, 8]) + bytes([0x00, 0x10, 0x00, 0x00, 0x10, 0x08, 0x30, 0x01])
        read = lambda address, length: (lsda + bytes(64))[address - 0x1040:address - 0x1040 + length]
        self.assertEqual(self.c.landing_pads(read, 0x1100, 0x1040), {0x1130})
        with self.assertRaises(ValueError):
            self.c.landing_pads(lambda a, n: (bytes([0x00]) + bytes(63))[:n], 0x1100, 0x1040)

    def test_image_landing_pads_read_the_lsda_through_the_file_mapping(self):
        # The same index and LSDA inside one file: __unwind_info at 0x200, the LSDA at file 0x40.
        blob = struct.pack('<7I', 1, 28, 0, 0, 0, 28, 2) + struct.pack('<3I', 0x100, 0, 52)
        blob += struct.pack('<3I', 0x200, 0, 60) + struct.pack('<II', 0x100, 0x40)
        lsda = bytes([0xff, 0x9b, 0x10, 0x01, 8]) + bytes([0x00, 0x10, 0x00, 0x00, 0x10, 0x08, 0x30, 0x01])
        data = bytearray(0x400)
        data[0x40:0x40 + len(lsda)] = lsda
        data[0x200:0x200 + len(blob)] = blob
        info = dict(segments=[dict(name='__TEXT', vmaddr=0x100000000, fileoff=0, filesize=0x400, sections=[
            dict(name='__unwind_info', offset=0x200, size=len(blob))])])
        va_to_off = lambda address, length: address - 0x100000000
        self.assertEqual(self.c.image_landing_pads(bytes(data), info, va_to_off), {0x100000130})
        self.assertEqual(self.c.image_landing_pads(bytes(data), dict(segments=[dict(name='__TEXT', sections=[])]),
                                                   va_to_off), set())


def segments(data):
    """Instruction sections, code signature and subtype, read independently."""
    _, _, subtype, _, ncmds, _ = struct.unpack_from('<6I', data)
    at, text, signature = 32, [], None
    for _ in range(ncmds):
        command, size = struct.unpack_from('<II', data, at)
        if command == 0x19:
            for index in range(struct.unpack_from('<I', data, at + 64)[0]):
                base = at + 72 + 80 * index
                addr, length, offset = struct.unpack_from('<QQI', data, base + 32)
                if struct.unpack_from('<I', data, base + 64)[0] & 0x80000400 and length:
                    text.append((addr, length, offset))
        elif command == 0x1d:
            signature = struct.unpack_from('<II', data, at + 8)
        at += size
    return subtype, text, signature


def code_directory(data, signature):
    offset = signature[0]
    magic, _, count = struct.unpack_from('>III', data, offset)
    assert magic == 0xfade0cc0
    for slot in range(count):
        kind, at = struct.unpack_from('>II', data, offset + 12 + 8 * slot)
        if kind == 0:
            cd = offset + at
            length, = struct.unpack_from('>I', data, cd + 4)
            return cd, length
    raise AssertionError('no CodeDirectory')


ORDINARY = {'braa': 'br', 'braaz': 'br', 'brab': 'br', 'brabz': 'br', 'blraa': 'blr', 'blraaz': 'blr',
            'blrab': 'blr', 'blrabz': 'blr', 'retab': 'ret', 'retaa': 'ret', 'pacga': 'mov'}
LOADS = ('ldr', 'ldur')
HINTS = {'pacibsp', 'autibsp', 'paciasp', 'autiasp', 'pacia1716', 'pacib1716', 'autia1716', 'autib1716',
         'xpaclri', 'paciaz', 'pacibz', 'autiaz', 'autibz'}


def pauth(mnemonic):
    return mnemonic in ORDINARY or mnemonic.startswith(('pac', 'aut', 'xpac', 'ldra')) or mnemonic in (
        'eretaa', 'eretab')


def check_image(case, original, output, report):
    """Every changed word is a lowered PAC instruction, every code page and the CodeDirectory rehash."""
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.skipdata = True
    case.assertEqual(len(original), len(output))
    subtype, text, signature = segments(original)
    case.assertEqual(subtype & 0xff, 2)
    case.assertEqual(segments(output)[0], 0)
    cd, cd_length = code_directory(original, signature)
    differ = np.frombuffer(original, dtype=np.uint8) != np.frombuffer(output, dtype=np.uint8)
    changed = {int(at) & ~3 for at in np.flatnonzero(differ)}
    inside = lambda at, start, length: start <= at < start + length
    edits = 0
    for at in sorted(changed):
        if at == 8 or inside(at, cd, cd_length):
            continue
        section = next(s for s in text if inside(at, s[2], s[1]))
        va = section[0] + at - section[2]
        old = next(decoder.disasm_lite(original[at:at + 4], va))[2]
        new = next(decoder.disasm_lite(output[at:at + 4], va))[2]
        case.assertTrue(pauth(old) and old not in HINTS, f'{old} at {va:#x}')
        if old.startswith('ldra'):
            case.assertIn(new, LOADS, f'{old} at {va:#x}')
        else:
            case.assertEqual(new, ORDINARY.get(old, 'nop'), f'{old} at {va:#x}')
        edits += 1
    case.assertEqual(edits, report['instruction_edits'])
    # PAC-shaped words left behind are the decoded table words the report kept.
    remaining = [f'{m}@{a:#x}' for addr, length, offset in text
                 for a, _, m, _ in decoder.disasm_lite(output[offset:offset + length], addr)
                 if pauth(m) and m not in HINTS]
    case.assertEqual(len(remaining), sum(report['kept'].values()), remaining[:8])
    # Code-page hashes and the CodeDirectory hash, recomputed here.
    version, _, hash_offset, _, special, slots, limit, hash_size, hash_type, _, page = struct.unpack_from(
        '>IIIIIIIBBBB', output, cd + 8)
    case.assertEqual((hash_size, hash_type, page), (32, 2, 12))
    case.assertEqual(limit, signature[0])
    for slot in range(slots):
        page_bytes = output[slot << 12:min((slot + 1) << 12, limit)]
        stored = output[cd + hash_offset + 32 * slot:cd + hash_offset + 32 * (slot + 1)]
        case.assertEqual(hashlib.sha256(page_bytes).digest(), stored, f'page {slot}')
    special_area = slice(cd + hash_offset - 32 * special, cd + hash_offset)
    case.assertEqual(original[special_area], output[special_area])
    case.assertEqual(hashlib.sha256(original[cd:cd + cd_length]).hexdigest()[:40], report['original_cdhash'])
    case.assertEqual(hashlib.sha256(output[cd:cd + cd_length]).hexdigest()[:40], report['cdhash'])
    case.assertEqual(report['trust_cache_entry']['cdhash'], report['cdhash'])


@unittest.skipUnless(os.environ.get('ZETA_USERLAND_REWRITE_DIR') and os.environ.get('ZETA_USERLAND_REWRITE_ROOT'),
                     'supply rewritten images and the workspace root')
class ActualRewriteTests(unittest.TestCase):
    def test_rewritten_images(self):
        directory = Path(os.environ['ZETA_USERLAND_REWRITE_DIR'])
        root = Path(os.environ['ZETA_USERLAND_REWRITE_ROOT'])
        reports = sorted(directory.glob('*.json'))
        self.assertTrue(reports)
        for path in reports:
            with self.subTest(image=path.stem):
                report = json.loads(path.read_text())
                report.setdefault('kept', report['code_proof']['kept'])
                original = (root / report['input']['path']).read_bytes()
                output = (directory / path.stem).read_bytes()
                self.assertEqual(hashlib.sha256(original).hexdigest(), report['input']['sha256'])
                self.assertEqual(hashlib.sha256(output).hexdigest(), report['output_sha256'])
                check_image(self, original, output, report)


@unittest.skipUnless(os.environ.get('ZETA_USERLAND_TREE_REPORT'), 'supply a rewrite-zeta-userland-tree report')
class ActualTreeRewriteTests(unittest.TestCase):
    """ZETA_USERLAND_TREE_REPORT: every image of a tree rewrite against the root it was read from."""
    def test_rewritten_tree(self):
        report = json.loads(Path(os.environ['ZETA_USERLAND_TREE_REPORT']).read_text())
        self.assertEqual(report['schema'], 'zeta-userland-tree-rewrite-v1')
        self.assertTrue(report['images'])
        root, output = Path(report['root']), Path(report['output'])
        for image in report['images']:
            with self.subTest(image=image['paths'][0]):
                original = (root / image['paths'][0].lstrip('/')).read_bytes()
                rewritten = (output / image['output'].lstrip('/')).read_bytes()
                self.assertEqual(hashlib.sha256(original).hexdigest(), image['input_sha256'])
                self.assertEqual(hashlib.sha256(rewritten).hexdigest(), image['output_sha256'])
                for other in image['paths'][1:]:
                    self.assertEqual(hashlib.sha256((root / other.lstrip('/')).read_bytes()).hexdigest(),
                                     image['input_sha256'])
                check_image(self, original, rewritten, image)


if __name__ == '__main__':
    unittest.main()
