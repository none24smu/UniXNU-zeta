"""Bounded coalesced layout for standalone split kexts; no image emission.

The legacy arm64 VM path has named regions for readonly headers, constants,
code, writable data and linkedit. Packing changes inter-segment distances;
every split-info reference must therefore be independently adjusted later.
"""
PAGE = 0x4000
U64 = (1 << 64) - 1
GROUPS = (
    ('__TEXT', '__PRELINK_TEXT', 1),
    ('__TEXT_EXEC', '__PLK_TEXT_EXEC', 5),
    # arm_vm_prot_init maps the gap after DATA_CONST up to native __TEXT
    # RWNX. Constants must follow code so this cannot erase execute mappings.
    ('__DATA_CONST', '__PLK_DATA_CONST', 1),
    ('__DATA', '__PRELINK_DATA', 3),
    ('__LINKEDIT', '__PLK_LINKEDIT', 1),
)
REQUIRED = {'__TEXT', '__TEXT_EXEC', '__LINKEDIT'}


def require(value, message):
    if not value:
        raise ValueError(message)


def align(value, alignment=PAGE):
    require(value >= 0 and alignment > 0 and alignment & (alignment - 1) == 0,
            'invalid alignment input')
    return (value + alignment - 1) & -alignment


def disjoint(spans):
    spans = sorted((start, start + size, name) for start, size, name in spans if size)
    for left, right in zip(spans, spans[1:]):
        require(left[1] <= right[0], f'overlapping layout: {left[2]} and {right[2]}')


def plan(native, modules, info_bytes=None):
    # Display families carry large personality dictionaries.
    info_bytes = info_bytes or max(0x10000, 0x8000 * len(modules or ()))
    require(modules and info_bytes > 0, 'empty module set or prelink metadata')
    native_spans = [(s['va'], s['size'], s['name']) for s in native.segments if s['size']]
    disjoint(native_spans)
    names = {s['name']: s for s in native.segments}
    require(len(names) == len(native.segments), 'duplicate native segment')
    for _, parent, _ in GROUPS:
        require(parent in names and names[parent]['size'] == names[parent]['filesize'] == 0,
                f'expected empty native {parent}')
        require(len(names[parent]['sections']) == 1, f'expected one {parent} section')
    require('__PRELINK_INFO' in names and names['__PRELINK_INFO']['size'] == 0,
            'native prelink metadata is already populated')
    reserved_base = names['__PRELINK_TEXT']['va']
    native_base = min(start for start, _, _ in native_spans)
    native_end = max(start + size for start, size, _ in native_spans)
    require(reserved_base % PAGE == 0 and reserved_base < native_base,
            'no aligned reserved prelink region below native kernel')
    expected = {name for name, _, _ in GROUPS}
    for identifier, image in modules.items():
        actual = {s['name'] for s in image.segments if s['size']}
        # Small kexts (e.g. Libm) carry no constants or no data; header,
        # code and linkedit are always required.
        require(REQUIRED <= actual <= expected,
                f'{identifier}: unsupported child segments {(actual - expected) | (REQUIRED - actual)}')
        require(len(image.segments) == len(actual), f'{identifier}: duplicate or empty child segment')
        for segment in image.segments:
            require(segment['va'] % PAGE == 0 and segment['size'] % PAGE == 0,
                    f'{identifier}: unaligned child segment')
            require(segment['filesize'] <= segment['size'], f'{identifier}: file bytes exceed VM span')
        text = next(s for s in image.segments if s['name'] == '__TEXT')
        require(text['va'] == image.base == 0 and text['fileoff'] == 0,
                f'{identifier}: header must be at original VA/file offset zero')
        require(text['filesize'] == text['size'], f'{identifier}: header BSS breaks dense scanner')
    readonly_bytes = sum(segment['size'] for image in modules.values() for segment in image.segments
                         if segment['name'] in ('__TEXT', '__TEXT_EXEC', '__DATA_CONST'))
    header_base = native_base - readonly_bytes
    require(header_base % PAGE == 0 and header_base >= reserved_base,
            'readonly groups exceed reserved prelink region')
    groups, mapping = [], {name: {} for name in modules}
    cursor = header_base
    for child_name, parent_name, protection in GROUPS:
        if child_name == '__DATA':
            require(cursor <= native_base, 'readonly prelink groups exceed reserved region')
            cursor = align(native_end)
        start = cursor
        children = []
        for identifier in sorted(modules):
            segment = next((s for s in modules[identifier].segments if s['name'] == child_name), None)
            if segment is None:
                continue
            cursor = align(cursor)
            require(cursor + segment['size'] <= U64, 'coalesced VM address overflow')
            entry = dict(original_va=segment['va'], new_va=cursor, size=segment['size'],
                         original_fileoff=segment['fileoff'], original_filesize=segment['filesize'],
                         parent=parent_name, segment=child_name)
            mapping[identifier][child_name] = entry
            children.append(dict(module=identifier, **entry))
            cursor += segment['size']
        groups.append(dict(segment=parent_name, va=start, size=cursor - start,
                           protection=protection, children=children))
    groups.append(dict(segment='__PRELINK_INFO', va=align(cursor), size=align(info_bytes),
                       protection=3, children=[]))
    require(groups[2]['va'] + groups[2]['size'] == native_base,
            'coalesced constants must immediately precede native text')
    all_spans = native_spans + [(g['va'], g['size'], g['segment']) for g in groups]
    disjoint(all_spans)
    low = min(v[0] for v in all_spans)
    high = max(v[0] + v[1] for v in all_spans)
    require(high - low <= 256 * 1024 * 1024 - 2 * 1024 * 1024,
            'layout exceeds current DarwinBoot parser window')
    for group in groups:
        require(not group['protection'] & 2 or not group['protection'] & 4,
                'writable executable prelink group')
    return dict(schema='zeta-coalesced-prelink-layout-v1', analysis_only=True,
                native=native.identity, modules={name: image.identity for name, image in modules.items()},
                groups=groups, mapping=mapping, vm_base=low, vm_end=high,
                vm_span_bytes=high - low, driver_loadable=False,
                requirements=['Complete split-info, chain and instruction adjustment coverage.',
                              'Verified native binding and shared ABI gates.',
                              'Qualified kmod extents, source interfaces and real lifecycle.'])


def translate(layout, identifier, address, width=1):
    require(width > 0, 'invalid translated width')
    matches = [s for s in layout['mapping'][identifier].values()
               if s['original_va'] <= address and address + width <= s['original_va'] + s['size']]
    require(len(matches) == 1, f'{identifier}: original address outside one segment: {address:#x}')
    segment = matches[0]
    return segment['new_va'] + address - segment['original_va']
