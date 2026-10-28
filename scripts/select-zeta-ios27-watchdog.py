#!/usr/bin/env python3
"""Add the exact original watchdogd CPU/header diagnostic.

Original signed files stay unchanged. This extends an explicitly selected
runtime-fixup table, requires an exact trusted input and complete code proof,
and grants neither general x1 conversion approval nor UI qualification.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from normalize_zeta_native_common import record, require
from zeta_text_fixups import parse_table, encode_table
from zeta_x1_compat import lower_pointer_off, lower_cssc_single
from zeta_userland_pauth import lower as lower_auth

HERE = Path(__file__).resolve().parent
SOURCE_SHA = '03c8eb8b3b3ef5e64d9cf452a4a0212d24ac30c10788e79deaad99930c80f14a'
SOURCE_CD = '0be506bab86845c35d8a285dd531860ca39eff0a'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--original', required=True, type=Path)
    parser.add_argument('--apple-trust-cache', required=True, type=Path, help='original raw version-2 Apple trust cache')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--emit-exact-helper-diagnostic', action='store_true')
    args = parser.parse_args()
    require(args.emit_exact_helper_diagnostic, 'explicit exact-helper diagnostic opt-in required')
    require(not args.output.exists(), 'preserve existing output')
    writer = load('watchdog_writer', 'rewrite-zeta-userland.py')
    group = load('watchdog_group', 'generate-zeta-ios27-text-fixups.py')
    raw = args.original.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE_SHA, 'watchdogd input fingerprint mismatch')
    info = writer.parse(raw, allow_x1_analysis=True)
    directory = writer.code_directory(raw, info)
    writer.verify_code_pages(raw, directory)
    old_hash = writer.cdhash(raw, directory)
    trusted = writer.trust_cache_entries(args.apple_trust_cache.read_bytes())
    require(old_hash.hex() == SOURCE_CD and old_hash in trusted, 'original signature/trust membership mismatch')
    plan = writer.plan(raw)
    require(not plan['code_proof']['anomalies'] and plan['code_proof']['x1_isa']['remaining_counts'] == {'cssc-trap': 1},
            'watchdogd code proof is incomplete')
    require(len(plan['edits']) == 870, 'unexpected helper instruction count')
    remaining = plan['code_proof']['x1_isa']['remaining_sites']
    require(len(remaining) == 1 and (remaining[0]['fileoff'], remaining[0]['word'], remaining[0]['mnemonic']) ==
            (0x26d8, '0x9ac86528', 'umax'), 'unexpected retained helper ISA')
    va_to_offset = writer.va_to_off(info)
    sections = writer.instruction_sections(info)
    edits = []
    for edit in plan['edits']:
        offset, pc = edit['fileoff'], int(edit['va'], 16)
        before, after = int(edit['original_word'], 16), int(edit['ordinary_word'], 16)
        require(edit['evidence'] in ('unwind', 'pointer', 'landing', 'stub', 'call', 'start', 'gap'), 'unproven helper edit')
        require(any(s['addr'] <= pc and pc + 4 <= s['addr'] + s['size'] for s in sections) and
                va_to_offset(pc, 4) == offset, 'edit outside instruction/file region')
        require(offset + 4 <= directory['code_limit'] and
                not any(start <= offset < start + size for start, size, kind in info['dice']), 'edit outside signed code')
        require(struct.unpack_from('<I', raw, offset)[0] == before, 'old source instruction changed')
        lowered = lower_pointer_off(before, 'off') or lower_cssc_single(before) or lower_auth(before)
        require(lowered is not None and lowered[1] == after and before != after, 'unknown helper lowering')
        edits.append((offset, struct.pack('<I', before), struct.pack('<I', after)))
    name = 'watchdogd'
    groups = group.grouped(name, edits)
    require(struct.unpack_from('<I', raw, 8)[0] == 0x8000000c, 'unexpected original architecture')
    groups.append((name, 8, struct.pack('<I', 0x8000000c), bytes(4)))
    base_manifest = args.base / 'manifest.json'
    base = json.loads(base_manifest.read_text())
    table = (args.base / 'text-fixups-ios27.bin').read_bytes()
    require(hashlib.sha256(table).hexdigest() == base['table_sha256'], 'base table changed')
    rows = parse_table(table)
    require(not any(row[0] == name for row in rows), 'helper is already selected')
    rows = sorted(rows + groups)
    blob = encode_table(rows)
    plan_bytes = (json.dumps(plan, indent=2) + '\n').encode()
    entry = dict(path='/usr/libexec/' + name, basename=name, original=record(args.original),
                 original_cdhash=old_hash.hex(), original_tc_attributes=list(trusted[old_hash]),
                 plan=dict(path=str((args.output / (name + '.plan.json')).resolve()),
                           sha256=hashlib.sha256(plan_bytes).hexdigest()),
                 descriptors=len(groups), instruction_edits=len(edits),
                 runtime_header_subtype='CPU_SUBTYPE_ARM64_ALL', retained_isa_unchanged={'cssc-trap': 1})
    result = dict(base, schema='zeta-ios27-watchdog-runtime-extension-v1', base_manifest=record(base_manifest),
                  files=base['files'] + [entry], descriptor_count=len(rows), table_sha256=hashlib.sha256(blob).hexdigest(),
                  table_bytes=len(blob), filename_count=len(set(row[0] for row in rows)),
                  extension_instructions=len(edits), extension_descriptors=len(groups), native_execution=False, required_cpu_policy='existing zeta-cssc-compat=2 handler for exact UMAX site')
    # No output or original-file mutation precedes complete validation.
    args.output.mkdir(parents=True)
    (args.output / (name + '.plan.json')).write_bytes(plan_bytes)
    (args.output / 'text-fixups-ios27.bin').write_bytes(blob)
    (args.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(records=len(rows), extension_groups=len(groups), extension_edits=len(edits)), indent=2))


if __name__ == '__main__':
    main()
