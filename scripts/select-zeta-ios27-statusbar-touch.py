#!/usr/bin/env python3
"""Prepare the opt-in Duo status-bar foreground touch workaround.

The exact stock constructor attaches a UIPointerInteraction to a foreground
UIView that covers this profile's full display. Replace that attachment with
the native setUserInteractionEnabled:NO call. This excludes the foreground
subtree from touches and loses its pointer interaction; it is an owner-profile
experiment, not a general status-bar policy or a claim of physical validation.
Original signed files remain unchanged. Nothing selects the output globally.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

from normalize_zeta_native_common import record, require
from zeta_dyld_cache import CacheFile
from zeta_text_fixups import encode_table, parse_table


HERE = Path(__file__).resolve().parent
NAME = 'dyld_shared_cache_arm64e_x1.36'
SOURCE_SHA = '1d370dca8541c976bfb0a0efbdeee3e9e6a1742166c8f48bfc362962c1412e7f'
SOURCE_CD = '79728157ccf930691fb6accbffbe43f662e2c9e0'
BASE_SHA = '72ab7f785e5baedee2ab2c4f1e6cebd2ccd25234fe8a76cc5962d3214740ae8f'
BASE_COUNT = 947711
OFFSET = 0x2623aa4
VA = 0x222a23aa4
BEFORE = bytes.fromhex('c20240f9e2945795')
AFTER = bytes.fromhex('02008052668e5795')
CONTEXT_OFFSET = OFFSET - 16
CONTEXT = bytes.fromhex(
    'e00313aaae385895b1f85b95f40300aa'
    'c20240f9e2945795fdf85b95626a75f8')
STUBS = (
    (0x228008e30, 0x7c08e30, 'addInteraction:',
     bytes.fromhex('6128e7b02100149172deff17200020d4')),
    (0x228007440, 0x7c07440, 'setUserInteractionEnabled:',
     bytes.fromhex('e1bee6f021003891eee4ff17200020d4')),
)


def file_va(cache_file, offset, size):
    matches = [address + offset - file_offset
               for address, length, file_offset, _maxprot, _initprot in cache_file.mappings
               if file_offset <= offset and offset + size <= file_offset + length]
    require(len(matches) == 1, 'source offset must map to exactly one cache region')
    return matches[0]


def branch_target(word, pc):
    require(word & 0xfc000000 == 0x94000000, 'expected immediate BL')
    immediate = word & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return pc + immediate * 4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path,
                        help='pinned native27-splashboard-selected1 directory')
    parser.add_argument('--cache-file', required=True, type=Path,
                        help='original signed dyld_shared_cache_arm64e_x1.36')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--emit-foreground-passthrough-experiment', action='store_true')
    args = parser.parse_args()
    require(args.emit_foreground_passthrough_experiment, 'explicit foreground experiment opt-in required')
    require(not args.output.exists() and not args.output.is_symlink(), 'preserve existing output')

    base_manifest = args.base / 'manifest.json'
    base = json.loads(base_manifest.read_text())
    require(base.get('schema') == 'zeta-ios27-splashboardd-runtime-extension-v1',
            'requires the pinned SplashBoard extension base')
    layout = base.get('layout', {})
    require(layout.get('native_pixels') == [2754, 1892] and
            layout.get('logical_points') == [1377, 946] and
            layout.get('point_scale') == 2 and layout.get('target_sbh_screen_type') == 32 and
            layout.get('artwork_subtype') == 2034 and layout.get('wide_native_orientation_basis') is True,
            'requires the measured Duo type32 wide native layout')
    table = (args.base / 'text-fixups-ios27.bin').read_bytes()
    require(hashlib.sha256(table).hexdigest() == BASE_SHA == base.get('table_sha256'),
            'pinned base table changed')
    rows = parse_table(table)
    require(len(rows) == BASE_COUNT == base.get('descriptor_count') and
            len(set(row[0] for row in rows)) == 90 == base.get('filename_count') and
            len(table) == base.get('table_bytes'), 'base descriptor metadata mismatch')

    require(args.cache_file.name == NAME, 'unexpected source cache basename')
    source = CacheFile(args.cache_file, allow_x1_analysis=True)
    require(hashlib.sha256(source.data).hexdigest() == SOURCE_SHA, 'original signed cache changed')
    spec = importlib.util.spec_from_file_location('statusbar_signature', HERE / 'rewrite-zeta-dyld-cache.py')
    signature = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signature)
    require(signature.verify_signature(source.data, *source.signature) == SOURCE_CD,
            'original cache signature mismatch')
    require(file_va(source, OFFSET, len(BEFORE)) == VA and
            source.data[CONTEXT_OFFSET:CONTEXT_OFFSET + len(CONTEXT)] == CONTEXT and
            source.data[OFFSET:OFFSET + len(BEFORE)] == BEFORE,
            'foreground constructor mapping or 32-byte context changed')
    for stub_va, stub_offset, selector, expected in STUBS:
        require(file_va(source, stub_offset, len(expected)) == stub_va and
                source.data[stub_offset:stub_offset + len(expected)] == expected,
                'original selector stub changed: ' + selector)
    require(struct.unpack_from('<I', AFTER)[0] == 0x52800002 and
            branch_target(struct.unpack_from('<I', BEFORE, 4)[0], VA + 4) == STUBS[0][0] and
            branch_target(struct.unpack_from('<I', AFTER, 4)[0], VA + 4) == STUBS[1][0],
            'native setter argument or BL target mismatch')
    require(not any(name == NAME and offset < OFFSET + len(BEFORE) and
                    OFFSET < offset + len(old) for name, offset, old, _new in rows),
            'foreground workaround overlaps an existing fixup')
    extended_rows = sorted(rows + [(NAME, OFFSET, BEFORE, AFTER)])
    require(len(extended_rows) == len(rows) + 1, 'must add exactly one native descriptor')
    blob = encode_table(extended_rows)
    entry = dict(basename=NAME, original=record(args.cache_file), original_cdhash=SOURCE_CD,
                 va=hex(VA), file_offset=hex(OFFSET), before=BEFORE.hex(), after=AFTER.hex(),
                 context_offset=hex(CONTEXT_OFFSET), context_before=CONTEXT.hex(),
                 kind='Duo status-bar foreground native interaction workaround')
    workaround = dict(
        scope='explicit Surface Duo owner profile; all newly constructed STUIStatusBar foregrounds',
        constructor='-[STUIStatusBar _prepareVisualProviderIfNeeded]',
        constructor_imp='0x222a234e4', native_setter='-[UIView setUserInteractionEnabled:]',
        setter_imp='0x1847d5bcc', setter_abi='v20@0:8B16', setter_stub='0x228007440',
        arc='x20 retains foreground; following objc_release_x20 ignores the void setter return',
        evidence='guarded live foreground flag receipts; owner physical Home navigation pending',
        physical_validated=False,
        tradeoffs=[
            'Replaces addInteraction:; UIPointerInteraction remains stored but unattached.',
            'Disables touch interaction throughout the foreground subtree, including status items.',
            'Existing foreground instances are not retroactively changed by this constructor fixup.',
            'Geometry and pixels are unchanged; this does not prove the intended native provider policy.',
        ],
        future_policy='Verify display exclusion shape and native provider selection; AxisAlignableSplit '
                      'uses a bounded foreground frame plus statusBar.layer and superlayer '
                      'setSkipHitTesting:YES. Do not force that provider without matching evidence.')
    result = dict(base, schema='zeta-ios27-duo-statusbar-touch-experiment-v1',
                  base_manifest=record(base_manifest), files=base['files'] + [entry],
                  descriptor_count=len(extended_rows), filename_count=len(set(row[0] for row in extended_rows)),
                  table_bytes=len(blob), table_sha256=hashlib.sha256(blob).hexdigest(),
                  extension_descriptors=1, extension_instructions=2,
                  statusbar_foreground_workaround=workaround, physical_validated=False,
                  native_execution=False)
    # All guards complete before creating an output. This never edits the source or active selection.
    args.output.mkdir(parents=True)
    (args.output / 'text-fixups-ios27.bin').write_bytes(blob)
    (args.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(records=len(extended_rows), extension_descriptors=1,
                          output=str(args.output), physical_validated=False), indent=2))


if __name__ == '__main__':
    main()
