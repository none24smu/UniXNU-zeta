#!/usr/bin/env python3
"""Build a bounded experimental ordinary-ARM64 prelink from qualified plans.

No device operations. Required reports must describe these exact bytes. This
uses normal XNU split-kext lifecycle and preserves the real personalities;
emission alone does not establish runtime compatibility or a mounted root.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import zeta_prelink_layout as L
import zeta_prelink_metadata as M
import zeta_prelink_relocate as R


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = sibling('closure', 'audit-zeta-apfs-closure.py')
S = sibling('split', 'audit-zeta-split-info.py')
P = sibling('pauth', 'audit-zeta-apfs-pauth.py')
A = C.A
APFS = 'com.apple.filesystems.apfs'
AMFI = 'com.apple.driver.AppleMobileFileIntegrity'
ZLIB = 'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib'
# Paired shared tables pinned per gated importer set; AMFI adds IODTNVRAM.
SHARED_TABLES = {frozenset({APFS}): 22, frozenset({APFS, AMFI}): 23, frozenset({APFS, AMFI, ZLIB}): 23}
# The exact KDK 25F84 AMFI slice. Its kmod start wrapper tail-branches through
# __realmain, which this build left empty (zero-fill), so OSKext start returns
# without registering AMFI. OSKext calls kmod_info.start(kmod_info, data); the
# exported early policy entry ignores both and returns 0, so retargeting that
# pointer is MODULE_START wiring. The security-extension pass then starts it
# before mac_late and lockdown seal the AMFI registrations.
AMFI_START = dict(
    sha256='36a4f3e2848990a454dae006b6ac5f82cce82b1e360b2999874036aa7a2187dc',
    kmod_info=0x58000, realmain=0x58a70, wrapper=0x45218, entry=0x3497c,
    wrapper_code='5f2403d5880000f008c12991100140f9700000b4d19f9cd2110a1fd700008052c0035fd6',
    entry_code='7f2303d5fd7bbfa9fd03009116fdff9700008052fd7bc1a8ff0f5fd6')

# _vnode_check_signature's "Using iOS Platform policy" branch (Mach-O platform 2)
# calls postValidation with platform identifier hardcoded 0, so every identity
# on its deny lists (securityd, suggestd, timed, locationd, CommCenter, ...) is
# refused whatever the code directory carries. Pass the identifier the owner
# signature writes (rewrite-zeta-userland.py PLATFORM_IDENTIFIER), the value the
# macOS branch reads from the code directory.
AMFI_IOS_PLATFORM = dict(
    at=0x3504c, old='04008052', new='44038052',  # mov w4, #0 -> mov w4, #26
    context=0x35038, context_code='e7feffd0e7d83f91e00314aae10315aae30317aa040080520500805246008052'
                                  '4e0e0094')


def importer_hashes(extra):
    inputs = extra['inputs']
    rows = inputs['importers'] if 'importers' in inputs else [inputs['apfs']]
    return {row.get('slice', row)['sha256'] for row in rows}


def gate(native, modules, closure, vtables, extra):
    L.require(closure['native']['sha256'] == native.identity['sha256'], 'stale closure native identity')
    L.require(closure['decode_complete'] and closure['binding']['static_binding_complete'],
              'closure has unresolved, ambiguous or invalid bindings')
    L.require(set(modules) == set(closure['actual_kdk_executables']), 'executable closure changed')
    L.require(vtables['inputs']['native']['sha256'] == native.identity['sha256'] and
              vtables['decode_complete'] and vtables['gate'] == 'identical_observed_slots',
              'primary ABI gate did not pass for this kernel')
    importers = frozenset(name for name in (APFS, AMFI, ZLIB) if name in modules)
    L.require(importers in SHARED_TABLES, 'unsupported shared-class importer set')
    L.require(importer_hashes(extra) == {closure['module_reports'][name]['candidate']['sha256'] for name in importers},
              'extended shared ABI gate covers different importers')
    L.require(extra['inputs']['native']['sha256'] == native.identity['sha256'] and
              extra['decode_complete'] and len(extra['gate']['identical']) == SHARED_TABLES[importers] and
              extra['gate']['paired_tables'] == SHARED_TABLES[importers] and
              not extra['gate']['instance_size_mismatches'], 'extended shared ABI gate did not pass')
    L.require(set(extra['gate']['missing_native_providers']) == {'AppleEffaceableStorage', 'CoreAnalyticsHub'},
              'unexpected missing class providers')
    for name, image in modules.items():
        L.require(closure['module_reports'][name]['candidate']['sha256'] == image.identity['sha256'],
                  f'stale module identity: {name}')


def retarget_amfi_start(image, layout, rewrite):
    """Point kmod_info.start at the real _amfi_register_mac_policy entry."""
    pin = AMFI_START
    L.require(image.identity['sha256'] == pin['sha256'], 'AMFI start binding is pinned to another slice')
    defined = {}
    for symbol in image.symbols:
        if not symbol['type'] & 0xe0 and symbol['type'] & 0xe == 0xe:
            defined.setdefault(symbol['name'], set()).add(symbol['address'])
    for name, key in (('_kmod_info', 'kmod_info'), ('__realmain', 'realmain'),
                      ('__start', 'wrapper'), ('_amfi_register_mac_policy', 'entry')):
        L.require(defined.get(name) == {pin[key]}, f'AMFI start symbol moved: {name}')
    for key in ('wrapper', 'entry'):
        code = bytes.fromhex(pin[key + '_code'])
        at = image.file_at(pin[key], len(code))
        L.require(image.data[at:at + len(code)] == code, f'AMFI {key} code differs')
    # kmod_info is pack(4); start at +0xb4 must rebase to the wrapper.
    start = image.file_at(pin['kmod_info'] + 0xb4, 8)
    rebased = [e for e in rewrite['proposed_edits'] if e['fileoff'] == start and e['width'] == 8]
    L.require(len(rebased) == 1 and int.from_bytes(bytes.fromhex(rebased[0]['new']), 'little') ==
              L.translate(layout, AMFI, pin['wrapper']), 'AMFI kmod start does not reach its wrapper')
    edit = rebased[0]
    rewrite['counts'][edit['reason']] -= 1
    edit.update(new=L.translate(layout, AMFI, pin['entry']).to_bytes(8, 'little').hex(),
                reason='start:_amfi_register_mac_policy')
    rewrite['counts'][edit['reason']] = 1
    return dict(kmod_start_fileoff=start, wrapper=hex(L.translate(layout, AMFI, pin['wrapper'])),
                entry=hex(L.translate(layout, AMFI, pin['entry'])))


def amfi_ios_platform_identifier(image, rewrite):
    """Give the iOS-platform postValidation call the owner platform identifier."""
    pin = AMFI_IOS_PLATFORM
    L.require(image.identity['sha256'] == AMFI_START['sha256'], 'AMFI platform edit is pinned to another slice')
    code = bytes.fromhex(pin['context_code'])
    context = image.file_at(pin['context'], len(code))
    L.require(image.data[context:context + len(code)] == code, 'AMFI iOS-platform postValidation call differs')
    at = image.file_at(pin['at'], 4)
    L.require(image.data[at:at + 4].hex() == pin['old'], 'AMFI platform identifier argument differs')
    L.require(not any(e['fileoff'] < at + 4 and at < e['fileoff'] + e['width'] for e in rewrite['proposed_edits']),
              'AMFI platform identifier argument overlaps a rewrite edit')
    rewrite['proposed_edits'].append(dict(fileoff=at, width=4, old=pin['old'], new=pin['new'],
                                          reason='amfi:ios-platform-identifier'))
    rewrite['counts']['amfi:ios-platform-identifier'] = 1
    return dict(fileoff=at, old=pin['old'], new=pin['new'])


def converted_module(image, identifier, layout, rewrite):
    L.require(rewrite['rewrite_coverage_complete'], 'incomplete rewrite plan')
    data = bytearray(image.data)
    for edit in rewrite['proposed_edits']:
        at, width = edit['fileoff'], edit['width']
        L.require(data[at:at + width].hex() == edit['old'], 'overlapping or stale byte edit')
        data[at:at + width] = bytes.fromhex(edit['new'])
    # All producers/consumers now use the explicitly unsigned ordinary ABI.
    struct.pack_into('<I', data, 8, 0)
    discarded = []
    for command in image.commands:
        kind, at = int(command['command'], 16), command['offset']
        if kind == 0x19:
            old_va, size = struct.unpack_from('<QQ', data, at + 24)
            name = bytes(data[at + 8:at + 24]).split(b'\0', 1)[0].decode()
            mapped = layout['mapping'][identifier][name]
            struct.pack_into('<Q', data, at + 24, mapped['new_va'])
            # File offsets remain module-relative, preserving LINKEDIT's
            # (new_vmaddr - original_fileoff) lookup basis in OSKext.
            for index in range(struct.unpack_from('<I', data, at + 64)[0]):
                section = at + 72 + index * 80
                address = struct.unpack_from('<Q', data, section + 32)[0]
                struct.pack_into('<Q', data, section + 32, mapped['new_va'] + address - old_va)
        elif kind in (0x1d, 0x1e, 0x26, 0x80000033, 0x80000034):
            # Original signature and address-encoded link metadata no longer
            # describe the rewritten image. Keep split-command presence for
            # the real kernel split mapping/kalloc path; consume its payload.
            off, count = struct.unpack_from('<II', data, at + 8)
            discarded.append(dict(command=hex(kind), original_offset=off, original_bytes=count))
            struct.pack_into('<II', data, at + 8, 0, 0)
        elif kind == 0xb:
            # No old relocation table may reapply an already completed fixup.
            L.require(struct.unpack_from('<I', data, at + 68)[0] == 0 and
                      struct.unpack_from('<I', data, at + 76)[0] == 0,
                      'unconsumed traditional external/local relocations')
    symoff = image.symtab[0]
    by_section = {section['index']: section for section in image.sections}
    for index, symbol in enumerate(image.symbols):
        if symbol['type'] & 0xe0 or symbol['type'] & 0xe != 0xe:
            continue
        section = by_section[symbol['section']]
        L.require(section['va'] <= symbol['address'] <= section['va'] + section['size'],
                  'section-defined symbol outside its declared section')
        value = L.translate(layout, identifier, section['va']) + symbol['address'] - section['va']
        struct.pack_into('<Q', data, symoff + index * 16 + 8, value)
    return bytes(data), discarded


def emit(native, modules, index, closure, vtables, extra, xnu_source, storage_source, crypto_source):
    gate(native, modules, closure, vtables, extra)
    layout = L.plan(native, modules)
    metadata, encoded, provenance = M.build(native, modules, layout, index, xnu_source, storage_source, crypto_source)
    converted, rewrites, consumed, start_binding, platform_edit = {}, {}, {}, None, None
    for name, image in modules.items():
        split = S.audit(image.data, image.identity['path'])
        pauth = P.audit_data(image.data, image.identity['path'])
        rewrite = R.module_plan(image, name, layout, split, pauth, closure['module_reports'][name])
        if name == AMFI:
            start_binding = retarget_amfi_start(image, layout, rewrite)
            platform_edit = amfi_ios_platform_identifier(image, rewrite)
        converted[name], consumed[name] = converted_module(image, name, layout, rewrite)
        rewrites[name] = rewrite
    output = bytearray(native.data)
    parent_offsets = {}
    for command in native.commands:
        if int(command['command'], 16) == 0x19:
            at = command['offset']
            parent_offsets[bytes(output[at + 8:at + 24]).split(b'\0', 1)[0].decode()] = at
    for group in layout['groups']:
        fileoff = L.align(len(output))
        output.extend(bytes(fileoff - len(output) + group['size']))
        if group['segment'] == '__PRELINK_INFO':
            output[fileoff:fileoff + len(encoded)] = encoded
        for child in group['children']:
            image = converted[child['module']]
            blob = image[child['original_fileoff']:child['original_fileoff'] + child['original_filesize']]
            destination = fileoff + child['new_va'] - group['va']
            output[destination:destination + len(blob)] = blob
        command = parent_offsets[group['segment']]
        L.require(struct.unpack_from('<I', output, command + 64)[0] == 1, 'parent section count changed')
        struct.pack_into('<4Q2I', output, command + 24, group['va'], group['size'], fileoff,
                         group['size'], group['protection'], group['protection'])
        struct.pack_into('<QQI', output, command + 72 + 32, group['va'], group['size'], fileoff)
        group['fileoff'] = fileoff
    # Validate final parent geometry and its untouched ordinary kernel symbols.
    parent = A.MachO(bytes(output), '<experimental-prelinked-kernel>')
    for name, image in modules.items():
        for segment in image.segments:
            mapping = layout['mapping'][name][segment['name']]
            at = parent.file_at(mapping['new_va'], segment['filesize'])
            expected = converted[name][segment['fileoff']:segment['fileoff'] + segment['filesize']]
            L.require(output[at:at + len(expected)] == expected, 'final child segment bytes differ')
    report = dict(schema='zeta-experimental-apfs-prelink-v1', native=native.identity,
                  output_sha256=hashlib.sha256(output).hexdigest(), output_bytes=len(output),
                  structurally_emitted=True, hardware_tested=False, stage6_complete=False,
                  layout=layout, metadata_provenance=provenance, metadata_entries=len(metadata['_PrelinkInfoDictionary']),
                  consumed_link_metadata=consumed,
                  amfi_start_binding=start_binding,
                  amfi_ios_platform_identifier=platform_edit,
                  rewrites={name: {key: value for key, value in plan.items() if key != 'proposed_edits'}
                            for name, plan in rewrites.items()},
                  limitations=['Experimental conversion; runtime driver and private BSD ABI remain unverified.',
                               'Original code signatures are invalidated and their commands cleared.',
                               'No separate constructor loop: normal OSKext and IOBSD matching must succeed.',
                               'Root signature/hash verification and actual mount remain independent gates.'] +
                              (['AMFI kmod start is retargeted to its real early entry; its runtime registration is unproven.']
                               if AMFI in modules else []))
    return bytes(output), report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'closure', 'vtables', 'extra-vtables', 'kdk-extensions', 'xnu-source', 'storage-source', 'crypto-source', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        native = A.MachO(args.native.read_bytes(), args.native)
        closure, vtables, extra = [json.loads(p.read_text()) for p in (args.closure, args.vtables, args.extra_vtables)]
        bundles = C.index_bundles(args.kdk_extensions)
        modules, index = {}, {}
        for name in closure['actual_kdk_executables']:
            node = bundles[name]
            sliced = C.V.Image(Path(node['executable']))
            modules[name] = A.MachO(sliced.data, node['executable'], candidate=True)
            index[name] = dict(plist_path=Path(node['metadata']['path']))
        output, report = emit(native, modules, index, closure, vtables, extra,
                              args.xnu_source, args.storage_source, args.crypto_source)
        (args.output / 'kernel.macho').write_bytes(output)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({key: report[key] for key in ('output_sha256', 'output_bytes', 'metadata_entries', 'hardware_tested')}))
    except (OSError, ValueError, KeyError, struct.error) as error:
        (args.output / 'rejected.json').write_text(json.dumps(dict(error=str(error), image_emitted=False), indent=2) + '\n')
        print(f'prelink rejected: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
