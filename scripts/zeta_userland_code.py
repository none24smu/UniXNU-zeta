"""Prove which words of a userland image's instruction sections are code.

Apple's current linker leaves LC_DATA_IN_CODE empty, while clang places
arm64e jump tables and hand-written decoder tables inside __text. A linear
sweep therefore cannot tell a table entry from an instruction. This walks
control flow from every declared function start, the entry point and the
defined symbols, and decodes the hardened arm64e jump-table dispatch exactly.
Words it never reaches are not proven code. Anything unusual is reported,
not guessed.

The linker records a function start for every __text atom, jump tables and
constant tables included, so function starts are only strong roots when a
nonzero __unwind_info encoding covers them. Every other root is accepted
only if a tentative walk from it stays on decodable, non-UDF instructions
outside every decoded table. Those roots come in two grades: code pointers
(chained-fixup rebase targets and adr/adrp+add addresses formed by proven
code) and bare function starts or symbols. Each proven word records the
grade of the root that reached it first. A sequential walk never crosses into another
function start, since calls to noreturn functions are followed directly by
the next atom, which may be a table; that start is judged as its own root.
A tentative walk that runs into a start other than after a call fails.
"""
import bisect
import re
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

LC_UNIXTHREAD, LC_FUNCTION_STARTS, LC_MAIN, LC_SYMTAB = 0x5, 0x26, 0x80000028, 0x2
LC_DYLD_CHAINED_FIXUPS, DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 0x80000034, 12
CONDITIONAL = ('cbz', 'cbnz', 'tbz', 'tbnz')
STOPS = ('ret', 'retab', 'retaa', 'eret', 'brk', 'udf', 'hlt')
INDIRECT = ('br', 'braa', 'braaz', 'brab', 'brabz')
CALLS = ('bl', 'blr', 'blraa', 'blraaz', 'blrab', 'blrabz')
TARGET = re.compile(r'#(-?0x[0-9a-f]+|-?[0-9]+)$')
# The hardened dispatch clang emits for arm64e, newest instruction last.
DISPATCH = (('adrp', r'x17, #(0x[0-9a-f]+)'), ('add', r'x17, x17, #(0x[0-9a-f]+)'),
            ('ldrsw', r'x16, \[x17, x16, lsl #2\]'), ('adr', r'x17, #(0x[0-9a-f]+)'),
            ('add', r'x16, x17, x16'), ('br', r'x16'))


def uleb128(data, at, end):
    value = shift = 0
    while True:
        if at >= end:
            raise ValueError('truncated ULEB128')
        byte = data[at]
        at += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, at


def seeds(data, info):
    """(strong, weak) roots: entry point and unwind-covered starts, then other starts and symbols."""
    text = next(s for s in info['segments'] if s['name'] == '__TEXT')
    starts, strong, symbols, at = set(), set(), set(), 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        if command == LC_FUNCTION_STARTS:
            offset, length = struct.unpack_from('<II', data, at + 8)
            cursor, address = offset, text['vmaddr']
            while cursor < offset + length and data[cursor]:
                delta, cursor = uleb128(data, cursor, offset + length)
                address += delta
                starts.add(address)
        elif command == LC_MAIN:
            strong.add(text['vmaddr'] + struct.unpack_from('<Q', data, at + 8)[0])
        elif command == LC_UNIXTHREAD:
            flavor, count = struct.unpack_from('<II', data, at + 8)
            if flavor != 6 or count != 68:
                raise ValueError('unsupported LC_UNIXTHREAD state')
            strong.add(struct.unpack_from('<Q', data, at + 16 + 32 * 8)[0])
        elif command == LC_SYMTAB:
            symoff, nsyms = struct.unpack_from('<II', data, at + 8)
            for index in range(nsyms):
                kind = data[symoff + 16 * index + 4]
                if not kind & 0xe0 and kind & 0xe == 0xe:
                    symbols.add(struct.unpack_from('<Q', data, symoff + 16 * index + 8)[0])
        at += size
    covering = unwind_encodings(data, info, text['vmaddr'])
    keys = sorted(covering)
    for address in starts:
        index = bisect.bisect_right(keys, address) - 1
        if index >= 0 and covering[keys[index]]:
            strong.add(address)
    return strong, (starts | symbols) - strong, starts


def unwind_encodings(data, info, text_base):
    """Function address -> compact unwind encoding, from __TEXT,__unwind_info."""
    section = next((s for g in info['segments'] for s in g['sections'] if s['name'] == '__unwind_info'), None)
    if section is None:
        return {}
    blob = data[section['offset']:section['offset'] + section['size']]
    version, common_off, common_count, _, _, index_off, index_count = struct.unpack_from('<7I', blob)
    if version != 1:
        raise ValueError('unsupported __unwind_info version')
    common = struct.unpack_from(f'<{common_count}I', blob, common_off)
    result = {}
    for i in range(index_count - 1):
        function, second, _ = struct.unpack_from('<III', blob, index_off + 12 * i)
        kind = struct.unpack_from('<I', blob, second)[0]
        if kind == 2:
            _, entries_off, count = struct.unpack_from('<IHH', blob, second)
            for j in range(count):
                offset, encoding = struct.unpack_from('<II', blob, second + entries_off + 8 * j)
                result[text_base + offset] = encoding
        elif kind == 3:
            _, entries_off, count, local_off, local_count = struct.unpack_from('<IHHHH', blob, second)
            local = struct.unpack_from(f'<{local_count}I', blob, second + local_off)
            for j in range(count):
                entry = struct.unpack_from('<I', blob, second + entries_off + 4 * j)[0]
                result[text_base + function + (entry & 0xffffff)] = (common + local)[entry >> 24]
        else:
            raise ValueError('unsupported __unwind_info page kind')
    return result


def pointer_targets(data, info):
    """Rebase targets of LC_DYLD_CHAINED_FIXUPS (arm64e userland24 chains)."""
    base = next(s for s in info['segments'] if s['name'] == '__TEXT')['vmaddr']
    targets, at = set(), 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        at += size
        if command != LC_DYLD_CHAINED_FIXUPS:
            continue
        offset = struct.unpack_from('<I', data, at - size + 8)[0]
        version, starts_offset = struct.unpack_from('<II', data, offset)
        if version != 0:
            raise ValueError('unsupported chained fixups version')
        image = offset + starts_offset
        for index in range(struct.unpack_from('<I', data, image)[0]):
            info_offset = struct.unpack_from('<I', data, image + 4 + 4 * index)[0]
            if not info_offset:
                continue
            seg = image + info_offset
            _, page_size, pointer_format, segment_offset, _, page_count = struct.unpack_from('<IHHQIH', data, seg)
            if pointer_format != DYLD_CHAINED_PTR_ARM64E_USERLAND24:
                raise ValueError(f'unsupported chained pointer format {pointer_format}')
            segment = next(s for s in info['segments'] if s['vmaddr'] - base == segment_offset)
            for page in range(page_count):
                start = struct.unpack_from('<H', data, seg + 22 + 2 * page)[0]
                if start == 0xffff:
                    continue
                cursor = segment['fileoff'] + page * page_size + start
                while True:
                    value = struct.unpack_from('<Q', data, cursor)[0]
                    if not value >> 62 & 1:
                        targets.add(base + (value & (0xffffffff if value >> 63 else 0x7ffffffffff)))
                    step = value >> 51 & 0x7ff
                    if not step:
                        break
                    cursor += 8 * step
    return targets


def materialized(insns, code):
    """Addresses formed by adr, or adrp then add on the same register, in proven code."""
    found = set()
    for pc in code:
        mnemonic, operands = insns[pc]
        if mnemonic == 'adr':
            found.add(int(operands.split('#')[1], 0))
        elif mnemonic == 'adrp' and pc + 4 in code:
            register, page = operands.split(', #')
            following = insns[pc + 4]
            prefix = f'{register}, {register}, #'
            if following[0] == 'add' and following[1].startswith(prefix):
                found.add(int(page, 0) + int(following[1][len(prefix):], 0))
    return found


def decode(data, sections):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.skipdata = True
    table = {}
    for section in sections:
        start = section['offset']
        for address, size, mnemonic, operands in decoder.disasm_lite(data[start:start + section['size']], section['addr']):
            table[address] = (mnemonic, operands)
    return table


def jump_table(insns, data, va_to_off, pc):
    """Decode the hardened dispatch ending at pc, or None if it is not one."""
    values = []
    for index, (mnemonic, pattern) in enumerate(DISPATCH):
        at = pc - 4 * (len(DISPATCH) - 1 - index)
        found = insns.get(at)
        match = found and found[0] == mnemonic and re.fullmatch(pattern, found[1])
        if not match:
            return None
        values += [int(group, 16) for group in match.groups()]
    page, low, anchor = values
    # The clamp: cmp x16, #N (or a register holding N) then csel x16, x16, xzr, ls.
    limit = None
    for at in range(pc - 24, pc - 24 - 4 * 8, -4):
        found = insns.get(at)
        if not found:
            break
        if found == ('csel', 'x16, x16, xzr, ls'):
            for before in range(at - 4, at - 4 * 6, -4):
                compare = insns.get(before)
                if compare and compare[0] == 'cmp' and compare[1].startswith('x16, '):
                    operand = compare[1][5:]
                    if operand.startswith('#'):
                        limit = int(operand[1:], 0)
                    else:
                        for setter in range(before - 4, before - 4 * 6, -4):
                            move = insns.get(setter)
                            if move and move[0] == 'mov' and move[1].startswith(operand + ', #'):
                                limit = int(move[1].split('#')[1], 0)
                                break
                    break
            break
    if limit is None:
        return None
    base = page + low
    start = va_to_off(base, 4 * (limit + 1))
    entries = struct.unpack_from(f'<{limit + 1}i', data, start)
    return dict(dispatch=pc, table=base, entries=limit + 1, anchor=anchor,
                targets=sorted({anchor + entry for entry in entries}))


def walk(insns, data, va_to_off, roots, code, data_words, strict, boundaries):
    """Follow control flow; a strict walk returns None instead of stopping at a doubtful word."""
    found_code, tables, anomalies, work = set(), [], [], list(roots)
    while work:
        pc = work.pop()
        while pc not in code and pc not in found_code:
            found = insns.get(pc)
            if found is None or found[0].startswith('.') or pc in data_words or (strict and found[0] == 'udf'):
                if strict:
                    return None
                kind = ('leaves_instruction_sections' if found is None else 'reaches_table' if pc in data_words
                        else 'reaches_undecodable_word')
                anomalies.append(dict(kind=kind, address=hex(pc)))
                break
            mnemonic, operands = found
            found_code.add(pc)
            target = TARGET.search(operands)
            if mnemonic == 'b':
                work.append(int(target.group(1), 0))
                break
            if mnemonic == 'bl' or mnemonic.startswith('b.') or mnemonic in CONDITIONAL:
                work.append(int(target.group(1), 0))
            elif mnemonic in STOPS:
                break
            elif mnemonic in INDIRECT:
                table = jump_table(insns, data, va_to_off, pc) if mnemonic == 'br' else None
                if table:
                    tables.append(table)
                    work += table['targets']
                break
            pc += 4
            if pc in boundaries:
                # Only a call to a noreturn function may run into the next atom.
                if strict and mnemonic not in CALLS:
                    return None
                break
    return found_code, tables, anomalies


def table_words(tables):
    words = set()
    for table in tables:
        words.update(range(table['table'], table['table'] + 4 * table['entries'], 4))
    return words


def prove(data, info, sections, va_to_off):
    """Returns (insns, code, table words, tables, anomalies, roots); code maps address to root grade."""
    insns = decode(data, sections)
    strong, weak, starts = seeds(data, info)
    return prove_roots(insns, data, va_to_off, strong, weak, starts, pointer_targets(data, info))


def prove_roots(insns, data, va_to_off, strong, weak, starts, pointers, called=()):
    """The proof from supplied roots. Strong roots are walked first. Then come code pointers and
    adr/adrp addresses, then calls from other images (called), then bare starts. Each root after the
    strong ones is accepted only after a strict tentative walk."""
    found, tables, anomalies = walk(insns, data, va_to_off, sorted(a for a in strong if a in insns), set(), set(),
                                    False, starts)
    code = dict.fromkeys(found, 'unwind')
    data_words = table_words(tables)
    tried, rejected = set(), []

    def attempt(root, grade):
        tried.add(root)
        result = walk(insns, data, va_to_off, [root], code, data_words, True, starts)
        if result is None or (code.keys() | result[0]) & table_words(result[1]):
            rejected.append(dict(address=hex(root), grade=grade))
            return False
        code.update(dict.fromkeys(result[0], grade))
        tables.extend(result[1])
        data_words.update(table_words(result[1]))
        return True

    accepted = dict(pointer=0, start=0)
    while True:
        candidates = sorted(a for a in pointers | materialized(insns, code)
                            if a in insns and a not in code and a not in data_words and a not in tried)
        if not candidates:
            break
        accepted['pointer'] += sum(attempt(root, 'pointer') for root in candidates)
    if called:
        accepted['call'] = 0
        for root in sorted(called):
            if root in insns and root not in code and root not in data_words and root not in tried:
                accepted['call'] += attempt(root, 'call')
    for root in sorted(weak):
        if root in insns and root not in code and root not in data_words and root not in tried:
            accepted['start'] += attempt(root, 'start')
    conflicts = sorted(code.keys() & data_words)
    if conflicts:
        raise ValueError(f'jump table overlaps proven code at {conflicts[0]:#x}')
    roots = dict(unwind=len(strong), pointer_accepted=accepted['pointer'], start_accepted=accepted['start'],
                 rejected=rejected)
    if called:
        roots['call_accepted'] = accepted['call']
    return insns, code, data_words, tables, anomalies, roots
