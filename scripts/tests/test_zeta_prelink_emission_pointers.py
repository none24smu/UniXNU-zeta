"""Independently inspect actual emitted pointer bytes, without emitter plans.

Set ZETA_PRELINK_EMISSION_DIR to a directory containing kernel.macho/report.json.
Original source paths in that report must still identify the immutable inputs.
The test uses the strict Mach-O/chain reader, but never imports the emitter,
layout translator, metadata generator or relocation writer. It derives maps
from the ACTUAL emitted child segment commands and decodes source fixups anew.
"""
from collections import defaultdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))


def sibling(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = sibling('emission_pointer_source_reader', 'audit-zeta-apfs.py')
V = sibling('emission_pointer_fat_reader', 'audit-zeta-apfs-vtables.py')


def require(condition, message):
    if not condition:
        raise ValueError(message)


AMFI = 'com.apple.driver.AppleMobileFileIntegrity'
ZLIB = 'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib'
# tmpfs registers its filesystem from kmod start only: a start and a stop slot.
TMPFS = 'com.apple.filesystems.tmpfs'
SANDBOX = 'com.apple.security.sandbox'
APPLEMATCH = 'com.apple.kext.AppleMatch'
# Lifecycle slots each optional module adds: start/stop plus constructors
# and destructors. The APFS closure alone has six kmods and 40 slots.
# Sandbox and AppleMatch have no __mod_init_func/__mod_term_func: kmod start and stop only.
EXTRA_LIFECYCLE = {AMFI: 10, ZLIB: 4, TMPFS: 2, SANDBOX: 2, APPLEMATCH: 2}
# The display closure (IOMobileGraphicsFamily and IOSurface roots, KDK 25F84).
EXTRA_LIFECYCLE.update({
    'com.apple.iokit.IOMobileGraphicsFamily': 22, 'com.apple.iokit.IOSurface': 34,
    'com.apple.driver.AppleARMPlatform': 76, 'com.apple.driver.AppleM2ScalerCSCDriver': 393,
    'com.apple.iokit.IOAVFamily': 118, 'com.apple.iokit.IOHDCPFamily': 21,
    'com.apple.driver.IODARTFamily': 16, 'com.apple.iokit.IOCECFamily': 8,
    'com.apple.driver.AppleIISController': 6, 'com.apple.iokit.IOAudio2Family': 6,
    'com.apple.iokit.IOReportFamily': 6, 'com.apple.iokit.IOSlowAdaptiveClockingFamily': 6,
    'com.apple.driver.AppleAudioClockLibs': 2, 'com.apple.kec.Libm': 2,
})
# Independently pinned: this AMFI slice's kmod start wrapper only tail-branches
# through its empty __realmain, so the emitter points kmod start at the real
# early policy entry instead. Nothing else may move a start pointer.
START_OVERRIDES = {
    (AMFI, '36a4f3e2848990a454dae006b6ac5f82cce82b1e360b2999874036aa7a2187dc'):
        ('__start', '_amfi_register_mac_policy'),
}


def defined_address(image, name):
    found = {s['address'] for s in image.symbols
             if s['name'] == name and s['section'] and not s['type'] & 0xe0}
    require(len(found) == 1, f'source symbol {name} not unique')
    return found.pop()


class EmissionPointers:
    def __init__(self, report):
        self.report = report
        native_path = Path(report['native']['path'])
        self.native = A.MachO(native_path.read_bytes(), native_path)
        require(self.native.identity['sha256'] == report['native']['sha256'], 'stale native identity')
        self.sources, self.decoded = {}, {}
        for name, identity in report['layout']['modules'].items():
            path = Path(identity['path'])
            image = A.MachO(V.Image(path).data, path, candidate=True)
            require(image.identity['sha256'] == identity['sha256'], 'stale source identity')
            self.sources[name] = image
            self.decoded[name] = A.audit(image, [])
        self.providers = {'native_source_kernel': self.native, **self.sources}
        self.exports = defaultdict(list)
        for provider, image in self.providers.items():
            for name, definitions in image.definitions().items():
                for address, absolute in definitions:
                    self.exports[name].append((provider, address, absolute))

    def verify(self, data):
        parent = A.MachO(data, '<emitted-pointer-audit>')
        info = next(s for s in parent.segments if s['name'] == '__PRELINK_INFO')
        raw = data[info['fileoff']:info['fileoff'] + info['filesize']].rstrip(b'\0')
        metadata = plistlib.loads(raw, fmt=plistlib.FMT_XML)
        entries = {e['CFBundleIdentifier']: e for e in metadata['_PrelinkInfoDictionary']}
        require(len(entries) == len(metadata['_PrelinkInfoDictionary']), 'duplicate metadata entry')
        executable_entries = {n for n, e in entries.items() if '_PrelinkExecutableLoadAddr' in e}
        require(executable_entries == set(self.sources), 'wrong executable metadata set')
        views = {}
        for name, source in self.sources.items():
            entry = entries[name]
            at = parent.file_at(entry['_PrelinkExecutableLoadAddr'], 32)
            magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data, at)
            require((magic, cpu, subtype, kind, reserved) == (0xfeedfacf, 0x100000c, 0, 0xb, 0),
                    'child is not ordinary ARM64 kext Mach-O')
            require(count == len(source.commands), 'child command inventory changed')
            require(32 + size <= entry['_PrelinkExecutableSize'], 'child commands leave wrapper')
            cursor, segments, sections, symtab = at + 32, {}, [], None
            for _ in range(count):
                command, length = struct.unpack_from('<II', data, cursor)
                require(length >= 8 and cursor + length <= at + 32 + size, 'bad child command geometry')
                if command == 0x19:
                    segment = data[cursor + 8:cursor + 24].split(b'\0', 1)[0].decode()
                    va, vmsize, fileoff, filesize, maximum, initial, nsections = struct.unpack_from('<4Q3I', data, cursor + 24)
                    require(segment not in segments, 'duplicate child segment')
                    segments[segment] = dict(va=va, size=vmsize, fileoff=fileoff, filesize=filesize,
                                             maximum=maximum, initial=initial)
                    require(length == 72 + nsections * 80, 'bad child segment command size')
                    for index in range(nsections):
                        offset = cursor + 72 + index * 80
                        address, nbytes, offset_in_file = struct.unpack_from('<QQI', data, offset + 32)
                        sections.append(dict(name=data[offset:offset + 16].split(b'\0', 1)[0].decode(),
                                             segment=segment, va=address, size=nbytes, fileoff=offset_in_file))
                elif command == 2:
                    symtab = struct.unpack_from('<4I', data, cursor + 8)
                cursor += length
            require(cursor == at + 32 + size, 'child command bytes not exactly consumed')
            require(set(segments) == {s['name'] for s in source.segments}, 'child segment set changed')
            for old in source.segments:
                new = segments[old['name']]
                require((new['size'], new['fileoff'], new['filesize'], new['initial'], new['maximum']) ==
                        (old['size'], old['fileoff'], old['filesize'], old['initial_protection'], old['maximum_protection']),
                        'child segment extent/protection/file basis changed')
            require(symtab == source.symtab, 'child symbol table file basis changed')
            require(len(sections) == len(source.sections), 'child section inventory changed')
            for old, new in zip(source.sections, sections):
                old_segment = next(s for s in source.segments if s['name'] == old['segment'])
                require((old['name'], old['segment'], old['size'], old['fileoff']) ==
                        (new['name'], new['segment'], new['size'], new['fileoff']), 'child section shape changed')
                require(new['va'] == segments[old['segment']]['va'] + old['va'] - old_segment['va'],
                        'child section address does not follow its actual segment')
            text = segments['__TEXT']
            require(entry['_PrelinkExecutableLoadAddr'] == entry['_PrelinkExecutableSourceAddr'] == text['va'],
                    'wrapper source/load address differs from actual child header')
            require(entry['_PrelinkExecutableSize'] == text['filesize'] == text['size'], 'wrong header wrapper extent')
            views[name] = dict(segments=segments, sections=sections, symtab=symtab)

        def translated(provider, va, width=1):
            source = self.sources[provider]
            choices = [s for s in source.segments if s['va'] <= va and va + width <= s['va'] + s['size']]
            require(len(choices) == 1, 'source pointer outside exactly one original segment')
            segment = choices[0]
            return views[provider]['segments'][segment['name']]['va'] + va - segment['va']

        rows, expected_at, lifecycle, kmods, bind_sites, structor_sites = [], {}, [], {}, [], []
        overrides = []
        for name, source in self.sources.items():
            override = START_OVERRIDES.get((name, source.identity['sha256']))
            if override:
                start_slot = defined_address(source, '_kmod_info') + 180
                wrapper, entry = (defined_address(source, symbol) for symbol in override)
            for row in self.decoded[name]['fixups']:
                source_va = int(row['address'], 16)
                at = parent.file_at(translated(name, source_va, 8), 8)
                if row['bind']:
                    require(self.decoded[name]['imports'][row['import_ordinal']]['library_ordinal'] == -2,
                            'unsupported source import namespace')
                    matches = self.exports[row['name']]
                    require(len(matches) == 1, 'source bind not independently unique')
                    provider, address, absolute = matches[0]
                    original_target = address + row['total_addend']
                    require(0 <= original_target < 1 << 64, 'bind target overflows')
                    require(absolute or self.providers[provider].mapped(original_target), 'bind target leaves provider')
                    expected = original_target if provider == 'native_source_kernel' or absolute else translated(provider, original_target)
                    bind_sites.append(at)
                else:
                    original_target = int(row['original_target_before_authentication'], 16)
                    require(original_target == int(row['original_target_without_high8'], 16), 'tagged source rebase')
                    expected = translated(name, original_target)
                    if override and source_va == start_slot:
                        require(original_target == wrapper, 'pinned kmod start no longer reaches its wrapper')
                        expected = translated(name, entry)
                        overrides.append(dict(module=name, at=at, wrapper=translated(name, wrapper), entry=expected))
                actual = struct.unpack_from('<Q', data, at)[0]
                require(actual == expected, f'{name}: pointer mismatch at emitted fileoff {at:#x}')
                expected_at[(name, source_va)] = (at, expected, row)

            defined_kmods = [(i, s) for i, s in enumerate(source.symbols)
                             if s['name'] == '_kmod_info' and s['section'] and not s['type'] & 0xe0]
            require(len(defined_kmods) == 1, 'source packed kmod definition not unique')
            index, symbol = defined_kmods[0]
            original_va = symbol['address']
            kmod_va = translated(name, original_va, 196)
            require(entries[name]['_PrelinkKmodInfo'] == kmod_va, 'metadata points at wrong packed kmod')
            kmod_at = parent.file_at(kmod_va, 196)
            old_at = source.file_at(original_va, 196)
            expected_record = bytearray(source.data[old_at:old_at + 196])
            for (provider, va), (at, expected, row) in expected_at.items():
                if provider == name and original_va <= va < original_va + 196:
                    require(va + 8 <= original_va + 196, 'fixup crosses packed kmod record')
                    struct.pack_into('<Q', expected_record, va - original_va, expected)
            require(data[kmod_at:kmod_at + 196] == expected_record, 'packed kmod nonpointer/zero metadata changed')
            require(struct.unpack_from('<QQQ', data, kmod_at + 156) == (0, 0, 0),
                    'packed address/size/hdr_size no longer original zero')
            linkedit = views[name]['segments']['__LINKEDIT']
            nlist_va = linkedit['va'] + source.symtab[0] + index * 16 - linkedit['fileoff']
            nlist_at = parent.file_at(nlist_va, 16)
            require(struct.unpack_from('<Q', data, nlist_at + 8)[0] == kmod_va, 'emitted nlist kmod address disagrees')
            slots = [('start', original_va + 180), ('stop', original_va + 188)]
            slots += [(section['name'], section['va'] + delta)
                      for section in source.sections if section['flags'] & 255 in (9, 10)
                      for delta in range(0, section['size'], 8)]
            for label, va in slots:
                require((name, va) in expected_at, 'lifecycle pointer has no source fixup')
                at, expected, row = expected_at[(name, va)]
                require(not row['bind'], 'lifecycle pointer unexpectedly binds outside module')
                require(any(s['va'] <= expected < s['va'] + s['size'] and s['initial'] & 4
                            for s in views[name]['segments'].values()), 'lifecycle pointer is not own executable code')
                lifecycle.append(dict(module=name, label=label, at=at, target=expected))
                if label not in ('start', 'stop'):
                    structor_sites.append(at)
            kmods[name] = dict(at=kmod_at, nlist_value_at=nlist_at + 8)
            rows.append(dict(module=name, fixups=len(self.decoded[name]['fixups']),
                             lifecycle_slots=len(slots), packed_kmod_va=hex(kmod_va)))
        return dict(rows=rows, chained_pointers=sum(r['fixups'] for r in rows), lifecycle=lifecycle,
                    lifecycle_slots=len(lifecycle), kmods=kmods, bind_sites=bind_sites,
                    structor_sites=structor_sites, start_overrides=overrides)


@unittest.skipUnless(os.environ.get('ZETA_PRELINK_EMISSION_DIR'), 'supply actual emitted fixture directory')
class ActualEmittedPointers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = Path(os.environ['ZETA_PRELINK_EMISSION_DIR'])
        cls.report = json.loads((directory / 'report.json').read_text())
        cls.data = (directory / 'kernel.macho').read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != cls.report['output_sha256']:
            raise AssertionError('Emitted fixture differs from its report')
        cls.audit = EmissionPointers(cls.report)
        cls.result = cls.audit.verify(cls.data)
        cls.mutations = []

    @classmethod
    def tearDownClass(cls):
        if os.environ.get('ZETA_PRELINK_POINTER_REPORT'):
            Path(os.environ['ZETA_PRELINK_POINTER_REPORT']).write_text(json.dumps({
                'output_sha256': cls.report['output_sha256'],
                'actual_emitted_chain_pointer_count': cls.result['chained_pointers'],
                'actual_emitted_lifecycle_pointer_count': cls.result['lifecycle_slots'],
                'modules': cls.result['rows'], 'rejected_mutations': cls.mutations,
                'emitter_or_relocation_writer_imported': False, 'runtime_verified': False,
            }, indent=2) + '\n')

    def reject_pointer_mutation(self, at, value, label):
        damaged = bytearray(self.data)
        struct.pack_into('<Q', damaged, at, value)
        # Deliberately bypass the outer report hash here: the pointer/metadata
        # checks themselves must detect the corruption, not a generic hash gate.
        with self.assertRaises(ValueError):
            self.audit.verify(bytes(damaged))
        self.mutations.append(label)

    def test_all_actual_source_chains_and_lifecycle_slots(self):
        extra = [name for name in EXTRA_LIFECYCLE if name in self.audit.sources]
        self.assertEqual(len(self.result['kmods']), 6 + len(extra))
        self.assertEqual(self.result['lifecycle_slots'], 40 + sum(EXTRA_LIFECYCLE[name] for name in extra))
        self.assertEqual(sum(row['label'] in ('start', 'stop') for row in self.result['lifecycle']), 12 + 2 * len(extra))

    def test_amfi_start_reaches_only_its_real_entry(self):
        if AMFI not in self.audit.sources:
            self.skipTest('AMFI is not in this emission')
        [override] = self.result['start_overrides']
        start = next(r for r in self.result['lifecycle'] if r['module'] == AMFI and r['label'] == 'start')
        self.assertEqual((start['at'], start['target']), (override['at'], override['entry']))
        self.reject_pointer_mutation(override['at'], override['wrapper'], 'amfi-start-back-to-empty-wrapper')

    def test_wrong_start_code_target_rejected(self):
        slots = [r for r in self.result['lifecycle'] if r['label'] == 'start']
        self.reject_pointer_mutation(slots[0]['at'], slots[1]['target'], 'start-to-other-module-code')

    def test_original_encoded_structor_rejected(self):
        at = self.result['structor_sites'][0]
        self.reject_pointer_mutation(at, 0x8010000000004000, 'encoded-arm64e-structor-left-unconverted')

    def test_modified_hdr_size_rejected(self):
        kmod = next(iter(self.result['kmods'].values()))
        self.reject_pointer_mutation(kmod['at'] + 172, 0x4000, 'packed-hdr-size-altered')

    def test_wrong_kmod_nlist_value_rejected(self):
        kmod = next(iter(self.result['kmods'].values()))
        self.reject_pointer_mutation(kmod['nlist_value_at'], 0, 'kmod-symbol-loses-relocation')

    def test_wrong_bound_pointer_rejected(self):
        at = self.result['bind_sites'][0]
        original = struct.unpack_from('<Q', self.data, at)[0]
        self.reject_pointer_mutation(at, original + 4, 'bind-to-wrong-mapped-address')

    def test_wrong_metadata_kmod_record_rejected(self):
        identifier = next(iter(self.audit.sources))
        record = self.result['rows'][0]['packed_kmod_va']
        needle = b'<key>_PrelinkKmodInfo</key><integer size="64">' + record.encode() + b'</integer>'
        replacement = b'<key>_PrelinkKmodInfo</key><integer size="64">' + hex(int(record, 16) + 4).encode() + b'</integer>'
        self.assertEqual(self.data.count(needle), 1, identifier)
        self.assertEqual(len(needle), len(replacement))
        damaged = self.data.replace(needle, replacement)
        with self.assertRaisesRegex(ValueError, 'metadata points at wrong packed kmod'):
            self.audit.verify(damaged)
        self.mutations.append('metadata-kmod-offset-by-four')


if __name__ == '__main__':
    unittest.main(verbosity=2)
