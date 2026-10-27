"""Read a split arm64e dyld shared cache: files, mappings, images and code roots.

Only what proving and rewriting the cache's code needs: the main file and
its subcaches, every mapping with its slide info, the image list, each
image's segments, instruction sections, function starts and unwind
encodings, the rebase targets of slide info version 5, and each file's
code signature location. Nothing here writes.

Structures follow dyld's include/mach-o/dyld_cache_format.h and
fixup-chains.h:
https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h
"""
import bisect
import mmap
from pathlib import Path
import struct

import numpy as np

import zeta_userland_code as code

LC_SEGMENT_64, LC_FUNCTION_STARTS = 0x19, 0x26
INSTRUCTIONS = 0x80000400
S_SYMBOL_STUBS = 8
OBJC_STUB = 32             # fast-mode __objc_stubs entry: adrp/ldr x1, adrp/add/ldr/braa x16, 2 brk
VM_PROT_EXECUTE = 4
SLIDE_V5_NO_REBASE = 0xffff
HEADER_MAPPINGS, HEADER_SIGNATURE, HEADER_MAPPING_SLIDE = 0x10, 0x28, 0x138
HEADER_SUBCACHES, HEADER_IMAGES = 0x188, 0x1c0
SUBCACHE_ENTRY = 56          # dyld_subcache_entry: uuid, cacheVMOffset, fileSuffix[32]


class CacheFile:
    def __init__(self, path, *, allow_x1_analysis=False):
        self.path = Path(path)
        self.handle = self.path.open('rb')
        self.data = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
        magic = self.data[:16].rstrip(b'\0')
        architecture = magic[7:].strip() if magic.startswith(b'dyld_v1') else b''
        if architecture not in (b'arm64e', b'arm64ex1'):
            self.data.close(); self.handle.close()
            raise ValueError(f'{self.path.name}: unsupported dyld cache architecture')
        self.architecture = 'arm64e.x1' if architecture == b'arm64ex1' else 'arm64e'
        if self.architecture == 'arm64e.x1' and not allow_x1_analysis:
            self.data.close(); self.handle.close()
            raise ValueError(f'{self.path.name}: arm64e.x1 is analysis-only; executable conversion is not qualified')
        offset, count = struct.unpack_from('<II', self.data, HEADER_MAPPINGS)
        self.mappings = [struct.unpack_from('<QQQII', self.data, offset + 32 * i) for i in range(count)]
        self.signature = struct.unpack_from('<QQ', self.data, HEADER_SIGNATURE)
        slide_offset, slide_count = struct.unpack_from('<II', self.data, HEADER_MAPPING_SLIDE)
        self.slid = [struct.unpack_from('<QQQQQQII', self.data, slide_offset + 56 * i) for i in range(slide_count)]


class Cache:
    def __init__(self, main, *, allow_x1_analysis=False):
        main = Path(main)
        self.files = [CacheFile(main, allow_x1_analysis=allow_x1_analysis)]
        self.architecture = self.files[0].architecture
        header = self.files[0].data
        offset, count = struct.unpack_from('<II', header, HEADER_SUBCACHES)
        for index in range(count):
            entry = offset + SUBCACHE_ENTRY * index
            suffix = header[entry + 24:entry + 56].split(b'\0', 1)[0].decode()
            item = CacheFile(str(main) + suffix, allow_x1_analysis=allow_x1_analysis)
            if item.architecture != self.architecture:
                item.data.close(); item.handle.close()
                raise ValueError('Mixed architectures in dyld cache family')
            self.files.append(item)
        self.regions = sorted((address, size, index, fileoff, maxprot)
                              for index, cache_file in enumerate(self.files)
                              for address, size, fileoff, maxprot, _ in cache_file.mappings)
        self.starts = [region[0] for region in self.regions]
        offset, count = struct.unpack_from('<II', header, HEADER_IMAGES)
        self.images = []
        for index in range(count):
            address, _, _, path_offset = struct.unpack_from('<QQQI', header, offset + 32 * index)
            self.images.append((address, header[path_offset:header.find(b'\0', path_offset)].decode()))

    def locate(self, address):
        """(file index, file offset, bytes left in the mapping) of an unslid address."""
        index = bisect.bisect_right(self.starts, address) - 1
        if index >= 0:
            start, size, file_index, fileoff, _ = self.regions[index]
            if address < start + size:
                return file_index, fileoff + address - start, start + size - address
        raise KeyError(f'{address:#x} is not mapped by the cache')

    def read(self, address, length):
        index, offset, room = self.locate(address)
        if room < length:
            raise ValueError(f'{address:#x}+{length:#x} crosses a mapping')
        return self.files[index].data[offset:offset + length]

    def executable_regions(self):
        return [(start, size, index, fileoff) for start, size, index, fileoff, prot in self.regions
                if prot & VM_PROT_EXECUTE]

    def slide_targets(self):
        """Sorted unique rebase targets of every slid mapping (slide info version 5)."""
        targets = []
        for index, cache_file in enumerate(self.files):
            for address, size, fileoff, info_offset, info_size, flags, _, _ in cache_file.slid:
                if not info_size:
                    continue
                data = cache_file.data
                version, page_size, count, value_add = struct.unpack_from('<III4xQ', data, info_offset)
                if version != 5:
                    raise ValueError(f'{cache_file.path.name}: slide info version {version}, expected 5')
                pages = struct.unpack_from(f'<{count}H', data, info_offset + 24)
                found = []
                for page, delta in enumerate(pages):
                    if delta == SLIDE_V5_NO_REBASE:
                        continue
                    at = fileoff + page * page_size + delta
                    while True:
                        raw = struct.unpack_from('<Q', data, at)[0]
                        found.append(raw & 0x3ffffffff)
                        step = (raw >> 52) & 0x7ff
                        if not step:
                            break
                        at += step * 8
                targets.append(np.array(found, dtype=np.uint64) + np.uint64(value_add))
        return np.unique(np.concatenate(targets)) if targets else np.zeros(0, dtype=np.uint64)


class Image:
    def __init__(self, cache, address, path):
        self.cache, self.address, self.path = cache, address, path
        magic, _, _, _, ncmds, sizeofcmds = struct.unpack('<6I', cache.read(address, 24))
        if magic != 0xfeedfacf:
            raise ValueError(f'{path}: no 64-bit Mach-O header at {address:#x}')
        commands = cache.read(address + 32, sizeofcmds)
        self.segments, self.sections, self.function_starts_command = {}, [], None
        at = 0
        for _ in range(ncmds):
            command, size = struct.unpack_from('<II', commands, at)
            if command == LC_SEGMENT_64:
                name = commands[at + 8:at + 24].split(b'\0', 1)[0].decode()
                vmaddr, vmsize, fileoff, _ = struct.unpack_from('<4Q', commands, at + 24)
                self.segments[name] = dict(vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff)
                for index in range(struct.unpack_from('<I', commands, at + 64)[0]):
                    base = at + 72 + 80 * index
                    addr, length, fileoff = struct.unpack_from('<QQI', commands, base + 32)
                    flags, _, reserved2 = struct.unpack_from('<III', commands, base + 64)
                    self.sections.append(dict(segment=name, name=commands[base:base + 16].split(b'\0', 1)[0].decode(),
                                              addr=addr, size=length, fileoff=fileoff, flags=flags, reserved2=reserved2))
            elif command == LC_FUNCTION_STARTS:
                self.function_starts_command = struct.unpack_from('<II', commands, at + 8)
            at += size

    def instruction_sections(self):
        """Instruction sections with the file and offset that hold them, all in one cache file."""
        found, files = [], set()
        for section in self.sections:
            if section['flags'] & INSTRUCTIONS and section['size']:
                index, offset, room = self.cache.locate(section['addr'])
                if room < section['size']:
                    raise ValueError(f'{self.path}: {section["name"]} crosses a mapping')
                files.add(index)
                found.append(dict(section, offset=offset, file=index))
        if len(files) > 1:
            raise ValueError(f'{self.path}: instruction sections span cache files')
        return found

    def function_starts(self):
        linkedit = self.segments.get('__LINKEDIT')
        if not self.function_starts_command or not self.function_starts_command[1] or not linkedit:
            return []
        dataoff, datasize = self.function_starts_command
        blob = self.cache.read(linkedit['vmaddr'] + dataoff - linkedit['fileoff'], datasize)
        starts, cursor, address = [], 0, self.segments['__TEXT']['vmaddr']
        while cursor < len(blob) and blob[cursor]:
            delta, cursor = code.uleb128(blob, cursor, len(blob))
            address += delta
            starts.append(address)
        return starts

    def unwind_encodings(self):
        section = next((s for s in self.sections if s['name'] == '__unwind_info'), None)
        if not section:
            return {}
        blob = self.cache.read(section['addr'], section['size'])
        info = dict(segments=[dict(name='__TEXT', vmaddr=0, sections=[
            dict(name='__unwind_info', offset=0, size=len(blob))])])
        return code.unwind_encodings(blob, info, self.segments['__TEXT']['vmaddr'])

    def landing_pads(self):
        """Exception landing pads named by the LSDAs that __unwind_info lists."""
        section = next((s for s in self.sections if s['name'] == '__unwind_info'), None)
        if not section:
            return set()
        lsdas = code.unwind_lsdas(self.cache.read(section['addr'], section['size']), self.segments['__TEXT']['vmaddr'])
        pads = set()
        for function, lsda in lsdas.items():
            pads |= code.landing_pads(self.cache.read, function, lsda)
        return pads

    def stub_entries(self):
        """Entry points of stub sections: S_SYMBOL_STUBS by their stub size, and fast-mode
        __objc_stubs when every entry has the fixed layout."""
        entries = set()
        for section in self.sections:
            if section['flags'] & 0xff == S_SYMBOL_STUBS and section['reserved2']:
                entries.update(range(section['addr'], section['addr'] + section['size'], section['reserved2']))
            elif section['name'] == '__objc_stubs' and section['size'] % OBJC_STUB == 0:
                words = np.frombuffer(self.cache.read(section['addr'], section['size']), dtype='<u4').reshape(-1, 8)
                selector = (words[:, 0] & 0x9f00001f) == 0x90000001      # adrp x1
                branch = (words[:, 5] == 0xd71f0a11) | (words[:, 5] == 0xd61f0200)   # braa x16, x17 / br x16
                if selector.all() and branch.all():
                    entries.update(range(section['addr'], section['addr'] + section['size'], OBJC_STUB))
        return entries

    def roots(self):
        """(strong, weak, starts): unwind-covered function starts, the other starts, all starts."""
        starts = self.function_starts()
        covering = self.unwind_encodings()
        keys = sorted(covering)
        strong = set()
        for start in starts:
            index = bisect.bisect_right(keys, start) - 1
            if index >= 0 and covering[keys[index]]:
                strong.add(start)
        return strong, set(starts) - strong, set(starts)


class Coverage:
    """Address ranges of code other proofs own; membership tests and a record of what was reached."""
    def __init__(self, ranges):
        ranges = sorted(ranges)
        self.begins = [begin for begin, end in ranges]
        self.ends = [end for begin, end in ranges]
        self.reached = set()

    def __contains__(self, address):
        index = bisect.bisect_right(self.begins, address) - 1
        return index >= 0 and address < self.ends[index]
