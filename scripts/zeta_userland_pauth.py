"""Lower every non-hint FEAT_PAuth instruction a userland image can hold.

With pointer authentication absent, keys never sign anything, so the
userland ABI only needs each instruction's effect on ordinary pointers:
- PAC*, AUT* and XPAC* leave the pointer unchanged: NOP.
- BRA*, BLRA* and RETA* branch to the unauthenticated register: BR, BLR, RET.
- PACGA computes a 32-bit MAC in the top half of Xd; MOVZ Xd, #0 gives every
  signer and verifier the same value.
- LDRAA/LDRAB load from Xn plus a signed 10-bit offset scaled by 8, with
  optional pre-index writeback: LDR (unsigned offset), LDUR (negative
  offset) or LDR pre-index, when the offset fits one of them.
ERETAA/ERETAB cannot appear at EL0, and LDRA offsets that fit no ordinary
load are refused rather than approximated. Hint-space forms (PACIBSP and
friends) are NOPs without FEAT_PAuth and are not this module's business.

Encodings: Arm Architecture Reference Manual for A-profile, C6.2 (PACIA,
AUTIA, XPACI, PACGA, BRAA, BLRAA, RETAA, LDRAA, LDR, LDUR, MOVZ).
"""
NOP, RET = 0xd503201f, 0xd65f03c0
DP1SRC = ('pacia', 'pacib', 'pacda', 'pacdb', 'autia', 'autib', 'autda', 'autdb',
          'paciza', 'pacizb', 'pacdza', 'pacdzb', 'autiza', 'autizb', 'autdza', 'autdzb', 'xpaci', 'xpacd')
BRANCHES = ((0xd61f081f, 0xfffffc1f, 'braaz', 0xd61f0000), (0xd61f0c1f, 0xfffffc1f, 'brabz', 0xd61f0000),
            (0xd63f081f, 0xfffffc1f, 'blraaz', 0xd63f0000), (0xd63f0c1f, 0xfffffc1f, 'blrabz', 0xd63f0000),
            (0xd71f0800, 0xfffffc00, 'braa', 0xd61f0000), (0xd71f0c00, 0xfffffc00, 'brab', 0xd61f0000),
            (0xd73f0800, 0xfffffc00, 'blraa', 0xd63f0000), (0xd73f0c00, 0xfffffc00, 'blrab', 0xd63f0000))


def decode_lr(word):
    """Known PAuth_LR encodings: (mnemonic, operands, ordinary-pointer word).

    Arm FEAT_PAuth_LR and LLVM AArch64 SignAuthFixedRegs/PCRel/ReturnPCRel.
    PC/SP are authentication modifiers only; once signing is consistently
    removed, LR stays an ordinary pointer. Immediate RET forms still terminate
    control flow. Register modifiers are read-only authentication inputs; under
    the explicit ordinary-pointer ABI their authentication becomes NOP/RET too.
    """
    if word & 0xfffff81f == 0xdac1901e:
        register=(word>>5)&31
        return ('autibsppcr' if word&0x400 else 'autiasppcr'), ('xzr' if register==31 else 'x'+str(register)), NOP
    if word & 0xfffffbe0 == 0xd65f0be0 and word&31!=31:
        return ('retabsppcr' if word&0x400 else 'retaasppcr'), 'x'+str(word&31), RET
    if word & 0xfffffbff == 0xdac1a3fe:
        return ('pacibsppc' if word & 0x400 else 'paciasppc'), '', NOP
    if word & 0xffc0001f in (0xf380001f, 0x5500001f):
        offset = -((word >> 5) & 0xffff) * 4
        key = 'b' if word & 0x200000 else 'a'
        if word & 0xffc0001f == 0x5500001f:
            return 'reta'+key+'sppc', '#'+str(offset), RET
        return 'auti'+key+'sppc', '#'+str(offset), NOP
    return None


def lower(word):
    """(mnemonic, ordinary word) for a non-hint PAC instruction, None for anything else.

    Raises ValueError for PAC encodings that have no exact one-word lowering."""
    lr = decode_lr(word)
    if lr:
        return lr[0], lr[2]
    if word & 0xffff0000 == 0xdac10000:
        opcode, rn = (word >> 10) & 0x3f, (word >> 5) & 31
        if opcode >= len(DP1SRC):
            return None
        if opcode >= 8 and rn != 31:
            raise ValueError(f'{word:#010x}: zero-modifier PAC form with Rn != 31 is unallocated')
        return DP1SRC[opcode], NOP
    if word & 0xffe0fc00 == 0x9ac03000:
        rd = word & 31
        return 'pacga', NOP if rd == 31 else 0xd2800000 | rd
    for value, mask, name, base in BRANCHES:
        if word & mask == value:
            rn = (word >> 5) & 31
            if rn == 31:
                raise ValueError(f'{word:#010x}: authenticated branch to register 31')
            return name, base | rn << 5
    if word in (0xd65f0bff, 0xd65f0fff):
        return ('retaa' if word == 0xd65f0bff else 'retab'), RET
    if word in (0xd69f0bff, 0xd69f0fff):
        raise ValueError(f'{word:#010x}: ERETAA/ERETAB cannot run at EL0')
    if word & 0xff200400 == 0xf8200400:
        name = 'ldrab' if word & 0x00800000 else 'ldraa'
        offset = ((word >> 22) & 1) << 9 | (word >> 12) & 0x1ff
        offset = (offset - 1024 if offset & 0x200 else offset) * 8
        writeback, registers = (word >> 11) & 1, word & 0x3ff
        if writeback and -256 <= offset <= 255:
            return name, 0xf8400c00 | (offset & 0x1ff) << 12 | registers
        if not writeback and offset >= 0:
            return name, 0xf9400000 | (offset // 8) << 10 | registers
        if not writeback and offset >= -256:
            return name, 0xf8400000 | (offset & 0x1ff) << 12 | registers
        raise ValueError(f'{word:#010x}: {name} offset {offset} fits no ordinary load')
    return None
