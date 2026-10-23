"""Bounded instruction lowering for an ordinary-pointer ABI experiment.

Only the fifteen forms observed in the pinned APFS and AMFI dependency artifacts are handled.
This is not pointer authentication emulation: input pointers must already be
canonical unsigned pointers, and all producers/consumers must share that ABI.
It does not relocate, bind, initialize or emit a loadable driver. Unknown PAC
forms must be rejected by the caller's independent instruction inventory.
"""
import struct

NOP = 0xd503201f
RET = 0xd65f03c0


def lower_word(word):
    exact = {0xd503237f: 'pacibsp', 0xd50323ff: 'autibsp', 0xd65f0fff: 'retab'}
    if word in exact:
        name = exact[word]
        return name, RET if name == 'retab' else NOP
    for base, name in ((0xdac10000, 'pacia'), (0xdac10800, 'pacda'),
                       (0xdac11000, 'autia'), (0xdac11800, 'autda')):
        if word & 0xfffffc00 == base:
            if word & 31 == 31:
                raise ValueError('unsupported zero-register PAC destination')
            return name, NOP
    for base, name in ((0xdac123e0, 'paciza'), (0xdac133e0, 'autiza'), (0xdac13be0, 'autdza'),
                       (0xdac143e0, 'xpaci'), (0xdac147e0, 'xpacd')):
        if word & 0xffffffe0 == base:
            if word & 31 == 31:
                raise ValueError('unsupported zero-register PAC destination')
            return name, NOP
    for base, name, result in ((0xd71f0800, 'braa', 0xd61f0000),
                               (0xd73f0800, 'blraa', 0xd63f0000)):
        if word & 0xfffffc00 == base:
            register = (word >> 5) & 31
            if register == 31:
                raise ValueError('unsupported zero-register branch destination')
            return name, result | (register << 5)
    if word & 0xfffffc1f == 0xd63f081f:
        register = (word >> 5) & 31
        if register == 31:
            raise ValueError('unsupported zero-register branch destination')
        return 'blraaz', 0xd63f0000 | (register << 5)
    return None


def is_pauth_mnemonic(name):
    return name.startswith(('pac', 'aut', 'xpac', 'braa', 'brab', 'blraa', 'blrab',
                            'retaa', 'retab', 'ldraa', 'ldrab'))


def plan_section(data, va, fileoff, disassembler):
    """Cross-check opcode classification against an independent decoder."""
    if len(data) % 4 or va % 4 or fileoff % 4:
        raise ValueError('unaligned executable section')
    rows = []
    expected = va
    for address, size, name, operands in disassembler.disasm_lite(data, va):
        if address != expected or size != 4 or name.startswith('.'):
            raise ValueError(f'incomplete executable instruction decode at {expected:#x}')
        offset = address - va
        word = struct.unpack_from('<I', data, offset)[0]
        result = lower_word(word)
        if is_pauth_mnemonic(name) != bool(result):
            raise ValueError(f'unsupported or inconsistent PAuth instruction {name} at {address:#x}')
        if result:
            if result[0] != name:
                raise ValueError(f'PAuth opcode/decoder disagreement at {address:#x}')
            rows.append(dict(va=hex(address), fileoff=fileoff + offset, mnemonic=name,
                             operands=operands, original_word=hex(word), ordinary_word=hex(result[1])))
        expected += 4
    if expected != va + len(data):
        raise ValueError(f'incomplete executable instruction decode at {expected:#x}')
    return rows
