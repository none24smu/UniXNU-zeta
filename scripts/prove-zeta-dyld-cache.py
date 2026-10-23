#!/usr/bin/env python3
"""Prove which PAC-shaped words of an arm64e dyld shared cache are code.

Each image is proven on its own with zeta_userland_code: its unwind-covered
function starts are strong roots. Slide-info rebase targets inside its
instruction sections and adr/adrp+add addresses formed by its proven code
are pointer roots. Exception landing pads from its LSDAs and the entries of
its stub sections are structural roots, and its other function starts are
bare roots. Words Capstone cannot decode are given to llvm-mc with every
A-profile feature: Apple AMX words and SME2 or newer SVE instructions are
straight-line code a walk steps over; branches stay undecodable. Last, code
left inside a proven atom after a proven terminator (dead epilogues and
error exits) is proven by the same strict walk. Images in
a cache call each other directly, so a walk that reaches another image's
code or a stub island records the target and stops there (Coverage). A
second pass re-proves every image that still holds unproven PAC words, with
the calls other images made into it as an extra root grade. The stub islands
are proven last, from the calls that reached them. Every PAC word in proven
code gets its ordinary lowering (zeta_userland_pauth). Unproven PAC words
are left as they are and reported: they are either data or code no proof
reaches, and rewriting data would corrupt it.

Results go to --work, one compressed numpy file per image plus a JSON
summary. Reads the cache only.
"""
import argparse
import bisect
from collections import Counter
import hashlib
import json
import multiprocessing
from pathlib import Path
import sys
import time

import numpy as np

import zeta_dyld_cache as dc
import zeta_userland_code as code
import zeta_userland_pauth as pauth

GRADES = ('unwind', 'pointer', 'landing', 'stub', 'call', 'start', 'gap')
PAC_MASKS = ((0xffff0000, 0xdac10000), (0xffe0fc00, 0x9ac03000), (0xfffff81f, 0xd61f081f),
             (0xfffff81f, 0xd63f081f), (0xfffff800, 0xd71f0800), (0xfffff800, 0xd73f0800),
             (0xfffffbff, 0xd65f0bff), (0xfffffbff, 0xd69f0bff), (0xff200400, 0xf8200400))

STATE = {}


def pac_candidates(words):
    """Indexes of words whose encoding is a non-hint PAC instruction class."""
    hit = np.zeros(words.shape, dtype=bool)
    for mask, value in PAC_MASKS:
        match = (words & np.uint32(mask)) == np.uint32(value)
        if value == 0xdac10000:
            match &= ((words >> np.uint32(10)) & np.uint32(0x3f)) <= np.uint32(0x11)
        hit |= match
    return np.nonzero(hit)[0]


def init(cache_path, ranges, targets, work):
    STATE['cache'] = dc.Cache(cache_path)
    STATE['coverage'] = dc.Coverage(ranges)
    STATE['targets'] = targets
    STATE['work'] = work


def section_va_to_off(cache, file_index):
    def va_to_off(address, length):
        index, offset, room = cache.locate(address)
        if index != file_index or room < length:
            raise ValueError(f'{address:#x} is not in the image file')
        return offset
    return va_to_off


def prove_code(cache, sections, strong, weak, starts, ordered, label):
    """Proof plus the lowered PAC words of the given sections."""
    file_index = sections[0]['file']
    data = cache.files[file_index].data
    va_to_off = section_va_to_off(cache, file_index)
    insns = code.decode(data, sections, code.llvm_oracle)
    targets = STATE['targets']
    pointers = set()
    for section in sections:
        low, high = np.searchsorted(targets, [section['addr'], section['addr'] + section['size']])
        pointers.update(int(t) for t in targets[low:high] if not int(t) & 3)
    # The image's own sections are decoded word for word, so only other code counts as external.
    coverage = STATE['coverage']
    coverage.reached = set()
    _, proven, data_words, tables, anomalies, roots = code.prove_roots(
        insns, data, va_to_off, strong, weak, starts, pointers, ordered, coverage, gaps=True)
    edits, unproven, unlowerable, kept = [], [], [], Counter()
    for section in sections:
        words = np.frombuffer(data, dtype='<u4', count=section['size'] // 4, offset=section['offset'])
        for index in pac_candidates(words):
            address = section['addr'] + 4 * int(index)
            word = int(words[index])
            if address in proven:
                try:
                    lowered = pauth.lower(word)
                except ValueError as error:
                    unlowerable.append(dict(va=hex(address), word=hex(word), reason=str(error)))
                    continue
                if lowered is None:
                    continue
                name, ordinary = lowered
                if insns[address][0] != name:
                    raise ValueError(f'{label}: decoder says {insns[address][0]} for {name} at {address:#x}')
                edits.append((address, section['offset'] + 4 * int(index), word, ordinary,
                              GRADES.index(proven[address])))
            elif address in data_words:
                kept['table'] += 1
            else:
                unproven.append((address, word))
    return dict(edits=edits, unproven=unproven, unlowerable=unlowerable, kept=dict(kept),
                reached=sorted(coverage.reached), file=file_index, proven_instructions=len(proven),
                tables=len(tables), roots=roots, anomalies=dict(Counter(a['kind'] for a in anomalies)))


def result_name(path):
    return hashlib.sha256(path.encode()).hexdigest()[:16]


def prove_image(job):
    """Prove one image, save its arrays, and return its summary and the external code it reached."""
    index, called = job
    cache = STATE['cache']
    address, path = cache.images[index]
    image = dc.Image(cache, address, path)
    sections = image.instruction_sections()
    if not sections:
        return index, None, []
    strong, weak, starts = image.roots()
    ordered = [('landing', image.landing_pads()), ('stub', image.stub_entries())]
    if called:
        ordered.append(('call', set(called)))
    started = time.time()
    result = prove_code(cache, sections, strong, weak, starts, ordered, path)
    result['seconds'] = round(time.time() - started, 2)
    reached = result['reached']
    name = result_name(path)
    result = save(STATE['work'], name, result)
    result.update(result_file=f'{name}.npz', reproven_with_calls=bool(called))
    return index, result, reached


def save(work, name, result):
    edits = np.array(result.pop('edits'), dtype=np.uint64).reshape(-1, 5)
    unproven = np.array(result.pop('unproven'), dtype=np.uint64).reshape(-1, 2)
    reached = np.array(result.pop('reached', []), dtype=np.uint64)
    np.savez_compressed(work / f'{name}.npz', edits=edits, unproven=unproven, reached=reached)
    result.update(edit_count=len(edits), unproven_count=len(unproven),
                  edits_by_evidence=dict(Counter(GRADES[int(g)] for g in edits[:, 4])) if len(edits) else {})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cache', required=True, type=Path, help='main cache file (subcaches beside it)')
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--only', action='append', help='prove only images whose path ends with this')
    args = parser.parse_args(argv)
    args.work.mkdir(parents=True, exist_ok=True)
    cache = dc.Cache(args.cache)
    images = [dc.Image(cache, address, path) for address, path in cache.images]
    ranges = [(s['addr'], s['addr'] + s['size']) for image in images for s in image.sections
              if s['flags'] & dc.INSTRUCTIONS and s['size']]
    islands = [(start, start + size, index, fileoff)
               for index, cache_file in enumerate(cache.files)
               for start, size, fileoff, _, _, flags, maxprot, _ in cache_file.slid if flags & 8]
    ranges += [(start, end) for start, end, _, _ in islands]
    ranges.sort()
    targets = cache.slide_targets()
    order = sorted(range(len(images)), key=lambda i: -sum(s['size'] for s in images[i].sections
                                                           if s['flags'] & dc.INSTRUCTIONS))
    if args.only:
        order = [i for i in order if any(images[i].path.endswith(o) for o in args.only)]
    summary = dict(schema='zeta-dyld-cache-proof-v1', cache=str(args.cache), images={})
    multiprocessing.set_start_method('fork', force=True)
    init(args.cache, ranges, targets, args.work)

    def run(jobs, label):
        results, reached = {}, {}
        with multiprocessing.Pool(args.jobs, initializer=init,
                                  initargs=(args.cache, ranges, targets, args.work)) as pool:
            for count, (index, result, found) in enumerate(pool.imap_unordered(prove_image, jobs), 1):
                if result is not None:
                    results[index], reached[index] = result, found
                if count % 200 == 0 or count == len(jobs):
                    print(f'{label}: {count}/{len(jobs)}', file=sys.stderr, flush=True)
        return results, reached

    results, reached = run([(i, ()) for i in order], 'own roots')
    inbound = set()
    for found in reached.values():
        inbound.update(found)
    owners = sorted((s['addr'], s['addr'] + s['size'], i) for i in results
                    for s in images[i].instruction_sections())
    begins = [begin for begin, _, _ in owners]
    called = {}
    for target in inbound:
        at = bisect.bisect_right(begins, target) - 1
        if at >= 0 and target < owners[at][1]:
            called.setdefault(owners[at][2], set()).add(target)
    again = [i for i in order if i in results and results[i]['unproven_count'] and called.get(i)]
    second, _ = run([(i, sorted(called[i])) for i in again], 'with calls')
    results.update(second)
    for index, result in results.items():
        summary['images'][images[index].path] = result
    # Stub islands: from the calls that reached them.
    island_results = []
    for start, end, file_index, fileoff in islands:
        roots = {t for t in inbound if start <= t < end}
        section = dict(name='island', addr=start, size=end - start, offset=fileoff, file=file_index)
        result = prove_code(cache, [section], set(), set(), set(), [('call', roots)], f'island {start:#x}')
        result.pop('reached')
        name = f'island-{start:x}'
        island_results.append(dict(save(args.work, name, dict(result, roots={'call': len(roots)})),
                                   address=hex(start), size=end - start, result_file=f'{name}.npz'))
    summary['islands'] = island_results
    totals = Counter()
    for entry in list(summary['images'].values()) + island_results:
        totals['edits'] += entry['edit_count']
        totals['unproven'] += entry['unproven_count']
        totals['unlowerable'] += len(entry['unlowerable'])
        for grade, count in entry['edits_by_evidence'].items():
            totals['edits:' + grade] += count
    summary['totals'] = dict(totals)
    (args.work / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps(summary['totals'], indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
