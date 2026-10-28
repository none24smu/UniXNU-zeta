#!/usr/bin/env python3
"""Select the exact original startup initializer with fail-closed erase-path stops.

The original --init no-op decision stays intact. Two deliberate B-to-self stops
prevent that command's erase paths from continuing. This is a temporary diagnostic,
not an implementation of obliteration or an unconditional success replacement.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from normalize_zeta_native_common import record, require
from zeta_text_fixups import parse_table, encode_table, MAX_ENTRIES
from zeta_x1_compat import lower_pointer_off, lower_cssc_single
from zeta_userland_pauth import lower as lower_auth

HERE = Path(__file__).resolve().parent
ORIGINAL_SHA = 'a343d1541e91dca9f4370fe0feab877043eaf320db69d017b20aa2f921780edb'
PLAN_SHA = '4a80cfdbf1e45969de91578e91dfc01a9af8355d4bf5bb2f63cd7d5ed90cd0a2'
BASE_SHA = 'd05ced63faf721c1c4637ca49bc012492c029285857a2844d4a5228fa709de01'
MAIN_SHA = '361c9c066e79b5c3401e8e510e0b44e8a36d55ece297dda8dacbc75f414cb400'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'plan', 'base', 'trust-cache', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    a = p.parse_args()
    require(not a.output.exists(), 'preserve existing results')
    require(record(a.original)['sha256'] == ORIGINAL_SHA, 'initializer original changed')
    require(record(a.plan)['sha256'] == PLAN_SHA, 'initializer plan changed')
    require(record(a.base / 'manifest.json')['sha256'] == BASE_SHA, 'base helper profile changed')
    writer = load('obliterator_writer', 'rewrite-zeta-userland.py')
    group = load('obliterator_group', 'generate-zeta-ios27-text-fixups.py')
    raw = a.original.read_bytes()
    plan = json.loads(a.plan.read_text())
    require(plan['input_sha256'] == ORIGINAL_SHA and not plan['code_proof']['anomalies'], 'incomplete code proof')
    require(plan['code_proof']['x1_isa']['remaining_counts'] == {'cssc-trap': 7}, 'unexpected retained ISA')
    info = writer.parse(raw, allow_x1_analysis=True)
    cd = writer.code_directory(raw, info)
    writer.verify_code_pages(raw, cd)
    cdhash = writer.cdhash(raw, cd)
    trusted = writer.trust_cache_entries(a.trust_cache.read_bytes())
    require(cdhash.hex() == 'b8cd6eeac89d98323ed578f9dcccbd1703821b9e' and cdhash in trusted, 'original signature/TC mismatch')
    translate = writer.va_to_off(info)
    sections = writer.instruction_sections(info)
    edits = []
    for edit in plan['edits']:
        pc, offset = int(edit['va'], 16), edit['fileoff']
        before, after = int(edit['original_word'], 16), int(edit['ordinary_word'], 16)
        require(edit['evidence'] == 'unwind', 'unexpected code-membership proof')
        require(any(s['addr'] <= pc and pc + 4 <= s['addr'] + s['size'] for s in sections), 'edit outside code')
        require(translate(pc, 4) == offset and offset + 4 <= cd['code_limit'], 'unsigned edit')
        require(not any(x <= offset < x + n for x, n, k in info['dice']), 'edit inside data-in-code')
        require(struct.unpack_from('<I', raw, offset)[0] == before, 'original word changed')
        lowered = lower_pointer_off(before, 'off') or lower_cssc_single(before) or lower_auth(before)
        require(lowered is not None and lowered[1] == after and before != after, 'unqualified instruction lowering')
        edits.append((offset, struct.pack('<I', before), struct.pack('<I', after)))
    require(len(edits) == 1035 and len(group.grouped('mobile_obliterator', edits)) == 928, 'initializer plan count changed')
    begin, end = translate(0x100001ca0, 4), translate(0x100002144, 4)
    require(hashlib.sha256(raw[begin:end]).hexdigest() == MAIN_SHA, 'original main function changed')
    # These original conditional edges remain byte-for-byte intact.
    edges = {0x100001e24: 0x360000a0, 0x100001e28: 0x34000253, 0x100001e38: 0x34001093}
    for pc, expected in edges.items():
        require(struct.unpack_from('<I', raw, translate(pc, 4))[0] == expected, 'no-op decision changed')
    stops = []
    for pc, before, reason in (
        (0x100001e3c, 0x94000111, 'before the first oblit-inprogress marker write'),
        (0x100001e9c, 0x52800000, 'before common erase-path preparation'),
    ):
        offset = translate(pc, 4)
        require(offset // 4096 == begin // 4096, 'stop and entry lowering must share one atomic validation page')
        require(struct.unpack_from('<I', raw, offset)[0] == before, 'stop original changed')
        require(not any(o <= offset < o + len(b) for o, b, r in edits), 'stop overlaps instruction lowering')
        # A self branch does not depend on user exception/signal recovery policy.
        edits.append((offset, struct.pack('<I', before), struct.pack('<I', 0x14000000)))
        stops.append(dict(pc=hex(pc), fileoff=offset, original_word=hex(before), replacement_word='0x14000000', instruction='B .', reason=reason))
    extra = group.grouped('mobile_obliterator', edits)
    require(len(extra) == 930, 'combined page-atomic extension changed')
    base = json.loads((a.base / 'manifest.json').read_text())
    previous = (a.base / 'text-fixups-ios27.bin').read_bytes()
    require(hashlib.sha256(previous).hexdigest() == base['table_sha256'], 'base table changed')
    table = encode_table(sorted(parse_table(previous) + extra))
    records = parse_table(table)
    require(len(records) == 33317, 'unexpected combined table size')
    for pc in edges:
        offset = translate(pc, 4)
        require(not any(n == 'mobile_obliterator' and o <= offset < o + len(b) for n, o, b, r in records), 'descriptor changes original no-op edge')
    require(any(n == 'mobile_obliterator' and o <= begin and begin + 4 <= o + len(b)
                and r[begin-o:begin-o+4] == struct.pack('<I', 0xd503201f)
                for n, o, b, r in records), 'entry PAC translation missing')
    file = dict(path='/usr/libexec/mobile_obliterator', basename='mobile_obliterator', original=record(a.original), original_cdhash=cdhash.hex(),
                original_tc_attributes=list(trusted[cdhash]), plan=record(a.plan), descriptors=930, instruction_edits=1035,
                diagnostic_stops=stops, retained_isa_unchanged={'cssc-trap': 7})
    result = dict(base, schema='zeta-ios27-initializer-noop-diagnostic-v1', base_manifest=record(a.base / 'manifest.json'),
                  descriptor_count=len(records), table_sha256=hashlib.sha256(table).hexdigest(), table_bytes=len(table),
                  extension_instructions=1035, extension_descriptors=930, files=base['files'] + [file],
                  filename_count=len({r[0] for r in records}), remaining_capacity=MAX_ENTRIES-len(records),
                  required_kernel_record_capacity=65536, kernel_rebuild_required=True,
                  original_files_changed=False, native_execution=False, successful_guard_skipped=False,
                  no_op_edges_unchanged=True, diagnostic_stop_behavior='self-loop until the host requests bootloader reboot',
                  whole_program_safety_proven=False,
                  limits=['Own-binary --init path only; imported initializers and asynchronous control transfers are separate.',
                          'Pre-init ephemeral detection may delete the separate NVRAM obliteration key.',
                          'The temporary erase-path stops must remain in the same page-atomic table as entry lowering.'])
    a.output.mkdir(parents=True)
    (a.output / 'text-fixups-ios27.bin').write_bytes(table)
    (a.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['descriptor_count', 'extension_descriptors', 'filename_count', 'remaining_capacity', 'no_op_edges_unchanged']}, indent=2))


if __name__ == '__main__':
    main()
