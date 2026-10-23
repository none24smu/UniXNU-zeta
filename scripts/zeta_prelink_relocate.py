"""Plan strict split-segment/chain/PAuth rewrites; never emit a loadable image.

Only the five relocation kinds observed in the pinned closure are admitted.
Every original operand is checked before proposing its new encoding. Split
pointer records own rebases; the closure binder separately owns bind sites.
"""
from collections import Counter
import struct

from zeta_prelink_layout import require, translate, U64


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def instruction(kind, word, old_pc, old_target, new_pc, new_target):
    require(old_pc % 4 == new_pc % 4 == 0, 'unaligned instruction address')
    if kind == 5:
        require(word & 0x9f000000 == 0x90000000, 'unsupported or relaxed ADRP')
        immediate = signed(((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2), 21)
        require((old_pc & ~4095) + immediate * 4096 == old_target & ~4095,
                'original ADRP does not reach declared target page')
        delta = ((new_target & ~4095) - (new_pc & ~4095)) // 4096
        require(-(1 << 20) <= delta < (1 << 20), 'ADRP target outside signed page21 range')
        encoded = delta & 0x1fffff
        return (word & 0x9f00001f) | ((encoded & 3) << 29) | ((encoded >> 2) << 5)
    if kind == 6:
        if word & 0xffc00000 == 0x91000000:
            scale = 1
        elif word & 0x3b000000 == 0x39000000:
            scale = 1 << (word >> 30)
            if scale == 1 and word & 0x04800000 == 0x04800000:
                scale = 16
        else:
            raise ValueError('unsupported or relaxed OFF12 opcode')
        original = ((word >> 10) & 4095) * scale
        require(original < 4096 and original == old_target & 4095,
                'original OFF12 does not match declared target offset')
        value = new_target & 4095
        require(value % scale == 0, 'OFF12 target violates access alignment')
        return (word & 0xffc003ff) | ((value // scale) << 10)
    if kind == 7:
        require(word & 0x7c000000 == 0x14000000, 'unsupported BR26 opcode')
        require(old_pc + signed(word & 0x3ffffff, 26) * 4 == old_target,
                'original BR26 does not reach declared target')
        delta = new_target - new_pc
        require(delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), 'BR26 target out of range')
        return (word & 0xfc000000) | ((delta // 4) & 0x3ffffff)
    raise ValueError(f'unsupported instruction relocation kind {kind}')


def module_plan(image, identifier, layout, split_report, pauth_report, closure_module=None):
    require(split_report['input']['sha256'] == image.identity['sha256'], 'split input hash differs')
    require(pauth_report['input']['sha256'] == image.identity['sha256'], 'PAuth input hash differs')
    require(split_report['coverage']['all_payload_bytes_accounted'] and
            split_report['chained_pointer_agreement']['complete'] and
            pauth_report['instruction_decode_complete'], 'incomplete relocation inputs')
    edits, counts, occupied = [], Counter(), []

    def add(fileoff, width, value, reason, original=None):
        require(0 <= fileoff <= len(image.data) - width, 'edit outside original file')
        before = image.data[fileoff:fileoff + width]
        if original is not None:
            require(before == original, 'original edit bytes differ')
        require(0 <= value < (1 << (8 * width)), 'replacement value overflows width')
        after = value.to_bytes(width, 'little')
        occupied.append((fileoff, fileoff + width, reason))
        edits.append(dict(fileoff=fileoff, width=width, old=before.hex(), new=after.hex(), reason=reason))
        counts[reason] += 1

    for row in split_report['references']:
        pc, target = row['source_va'], row['target_va']
        new_pc = translate(layout, identifier, pc, row['width'])
        new_target = translate(layout, identifier, target)
        original = bytes.fromhex(row['original_bytes'])
        if row['kind'] in (5, 6, 7):
            value = instruction(row['kind'], int.from_bytes(original, 'little'), pc, target, new_pc, new_target)
        elif row['kind'] in (2, 13):
            pointer = row['format7']
            require(int(pointer['target_without_high8'], 16) == target and
                    int(pointer['target_before_authentication'], 16) == target,
                    'tagged or inconsistent original rebase target')
            value = new_target
        else:
            raise ValueError(f'unsupported split kind {row["kind"]}')
        add(row['source_fileoff'], row['width'], value, 'split:' + row['kind_name'], original)
    unresolved = []
    if closure_module is not None:
        require(closure_module['candidate']['sha256'] == image.identity['sha256'], 'binder input hash differs')
        for row in closure_module['fixups']:
            if not row['bind']:
                continue
            if row['closure_binding_status'] != 'resolved':
                unresolved.append(dict(fixup=row['index'], status=row['closure_binding_status']))
                continue
            provider = row['closure_provider']
            target = int(row['closure_target_original_address_before_authentication'], 16)
            value = target if provider == 'native_source_kernel' else translate(layout, provider, target)
            require(0 <= value <= U64, 'bound target overflows uint64')
            add(row['file_offset'], 8, value, 'bind', int(row['raw'], 16).to_bytes(8, 'little'))
    for row in pauth_report['edits']:
        add(row['fileoff'], 4, int(row['ordinary_word'], 16), 'pauth:' + row['mnemonic'],
            int(row['original_word'], 16).to_bytes(4, 'little'))
    ordered = sorted(occupied)
    for previous, current in zip(ordered, ordered[1:]):
        require(previous[1] <= current[0], f'overlapping edit ownership: {previous[2]} / {current[2]}')
    return dict(schema='zeta-split-relocation-plan-v1', input=image.identity, analysis_only=True,
                proposed_edits=edits, counts=dict(counts), changed_sites=sum(e['old'] != e['new'] for e in edits),
                unresolved=unresolved, binding_included=closure_module is not None,
                rewrite_coverage_complete=closure_module is not None and not unresolved,
                driver_loadable=False,
                limitations=['Header/section/nlist metadata, parent emission, source interfaces and lifecycle still require qualification.',
                             'Canonical unsigned pointers replace authentication; this does not emulate PAC security.'])
