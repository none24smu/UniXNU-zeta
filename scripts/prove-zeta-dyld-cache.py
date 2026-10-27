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
import struct
import time

import numpy as np

import zeta_dyld_cache as dc
import zeta_userland_code as code
import zeta_userland_pauth as pauth
import zeta_x1_compat as x1
import zeta_x1_rcpc as rcpc

GRADES = ('unwind', 'pointer', 'landing', 'stub', 'call', 'start', 'gap')
PAC_MASKS = ((0xffff0000, 0xdac10000), (0xffe0fc00, 0x9ac03000), (0xfffff81f, 0xd61f081f),
             (0xfffff81f, 0xd63f081f), (0xfffff800, 0xd71f0800), (0xfffff800, 0xd73f0800),
             (0xfffffbff, 0xd65f0bff), (0xfffffbff, 0xd69f0bff), (0xff200400, 0xf8200400),
             (0xfffff81f,0xdac1901e),(0xfffffbe0,0xd65f0be0),(0xfffffbff,0xdac1a3fe),(0xffc0001f,0xf380001f),(0xffc0001f,0x5500001f))

STATE = {}


def pac_candidates(words, experimental_x1=False):
    """Indexes of words whose encoding is a non-hint PAC instruction class."""
    hit = np.zeros(words.shape, dtype=bool)
    for mask, value in PAC_MASKS:
        match = (words & np.uint32(mask)) == np.uint32(value)
        if value == 0xdac10000:
            match &= ((words >> np.uint32(10)) & np.uint32(0x3f)) <= np.uint32(0x11)
        hit |= match
    if experimental_x1:
        hit |= ((words & np.uint32(0xffe0e000))==np.uint32(0x9a002000)) | ((words & np.uint32(0xffe0e000))==np.uint32(0xda002000)) | ((words & np.uint32(0xffe08000))==np.uint32(0x9b600000))
        cssc_hit = np.zeros(words.shape, dtype=bool)
        for mask, values in [(0x7ffffc00, (0x5ac01800,0x5ac02000,0x5ac01c00)),
                (0x7fe0fc00, (0x1ac06000,0x1ac06400,0x1ac06800,0x1ac06c00)),
                (0x7ffc0000, (0x11c00000,0x11c40000,0x11c80000,0x11cc0000))]:
            masked = words & np.uint32(mask)
            for value in values:
                cssc_hit |= masked == np.uint32(value)
        for index in np.nonzero(cssc_hit)[0]:
            if x1.lower_cssc_single(int(words[index])) is not None:
                hit[index] = True
    return np.nonzero(hit)[0]


def init(cache_path, ranges, targets, work, experimental_x1=False):
    STATE['experimental_x1']=experimental_x1
    STATE['cache'] = dc.Cache(cache_path,allow_x1_analysis=experimental_x1)
    noreturn={}
    if experimental_x1:
        for address,path in STATE['cache'].images:
            if path.endswith('/libsystem_c.dylib'):
                noreturn.update(dc.Image(STATE['cache'],address,path).export_addresses({'___assert_rtn','___stack_chk_fail','_abort'}))
            elif path.endswith('/libc++abi.dylib'):
                # Itanium C++ ABI throw/rethrow never return normally. Landing
                # pads remain independent roots; no arbitrary call is terminal.
                noreturn.update(dc.Image(STATE['cache'],address,path).export_addresses({'__ZSt9terminatev','___cxa_throw','___cxa_rethrow'}))
            elif path.endswith('/libsystem_kernel.dylib'):
                exits=dc.Image(STATE['cache'],address,path).export_addresses({'__exit','___exit'})
                # Darwin syscall1 terminates the process; bind the name to its
                # actual MOV X16,#1;SVC #0x80 stub, not an arbitrary export alias.
                for name,target in exits.items():
                    if STATE['cache'].read(target,8)!=struct.pack('<II',0xd2800030,0xd4001001):
                        raise ValueError('exit export does not match Darwin syscall1 stub')
                    noreturn[name]=target
    STATE['noreturn_exports']=noreturn
    STATE['coverage'] = dc.Coverage(ranges,STATE['cache'],allow_detached_stubs=experimental_x1,noreturn_exports=noreturn.values())
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
        for index in pac_candidates(words,STATE.get('experimental_x1',False)):
            address = section['addr'] + 4 * int(index)
            word = int(words[index])
            if address in proven:
                try:
                    lowered = ((x1.lower_pointer_off(word,'off') or x1.lower_cssc_single(word)) if STATE.get('experimental_x1') else None) or pauth.lower(word)
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
    groups=[]
    if STATE.get('experimental_x1') and label==rcpc.IMAGE:
        image=dc.Image(cache,next(a for a,p in cache.images if p==label),label)
        intervals=[(root,root+len(words)*4) for root,_,words in rcpc.FUNCTIONS]
        # Targeted static entry checks over the original cache, never rewritten
        # instructions. A later writer must authorize the explicit typed policy.
        incoming=rcpc.incoming_transfers(cache,intervals)
        groups=rcpc.plan(cache,image,proven,incoming,pointers|code.materialized(insns,proven),image.landing_pads(),tables)
        coordinated={}
        for group in groups:
            for index,(old,new) in enumerate(zip(group['original_words'],group['translated_words'])):
                if old==new:continue
                pc=group['root']+index*4
                coordinated[pc]=(pc,va_to_off(pc,4),old,new,GRADES.index(proven[pc]))
        edits=[row for row in edits if row[0] not in coordinated]+list(coordinated.values())
    isa={}
    if STATE.get('experimental_x1'):
        replacements={e[0]:e[3] for e in edits}
        rows=[]
        for section in sections:
            for address in range(section['addr'],section['addr']+section['size'],4):
                if address not in proven:continue
                offset=section['offset']+address-section['addr']
                word=struct.unpack_from('<I',data,offset)[0]
                rows.append((address,offset,word,replacements.get(address,word),insns[address][0]))
        rejected=x1.rejected_by_baseline(r[3] for r in rows)
        counts=Counter();examples={};mnemonics=Counter()
        for address,offset,word,ordinary,mnemonic in rows:
            family=x1.retained_feature(ordinary,mnemonic if ordinary==word else '')
            if ordinary not in rejected and not family:continue
            kind='cssc-trap' if x1.cssc(word) else 'retained-'+family if family else 'unknown-isa'
            counts[kind]+=1
            mnemonics[kind+':'+mnemonic]+=1
            if len(examples.setdefault(kind,[]))<16:
                examples[kind].append(dict(va=hex(address),fileoff=offset,word=hex(word),mnemonic=mnemonic))
        isa=dict(remaining_counts=dict(counts),mnemonics=dict(mnemonics),examples=examples)
    return dict(edits=edits, unproven=unproven, unlowerable=unlowerable, kept=dict(kept),
                reached=sorted(coverage.reached), file=file_index, proven_instructions=len(proven),
                tables=len(tables), roots=roots, x1_isa=isa, rcpc2_function_aot=groups,
                anomaly_examples=anomalies[:32], anomalies=dict(Counter(a['kind'] for a in anomalies)))


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
    if STATE.get('experimental_x1'):
        (STATE['work']/f'{name}.json').write_text(json.dumps(dict(result,image=path),indent=2)+'\n')
    return index, result, reached


def save(work, name, result):
    edits = np.array(result.pop('edits'), dtype=np.uint64).reshape(-1, 5)
    unproven = np.array(result.pop('unproven'), dtype=np.uint64).reshape(-1, 2)
    reached = np.array(result.pop('reached', []), dtype=np.uint64)
    np.savez_compressed(work / f'{name}.npz', edits=edits, unproven=unproven, reached=reached)
    result.update(result_sha256=hashlib.sha256((work/f'{name}.npz').read_bytes()).hexdigest(),edit_count=len(edits), unproven_count=len(unproven),
                  edits_by_evidence=dict(Counter(GRADES[int(g)] for g in edits[:, 4])) if len(edits) else {})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cache', required=True, type=Path, help='main cache file (subcaches beside it)')
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--experimental-x1-plan',action='store_true',help='read-only x1 code/ISA plan; never emits executable cache')
    parser.add_argument('--only', action='append', help='prove only images whose path ends with this')
    args = parser.parse_args(argv)
    args.work.mkdir(parents=True, exist_ok=True)
    tool_paths=[Path(__file__),Path(dc.__file__),Path(code.__file__),Path(pauth.__file__),Path(x1.__file__),Path(rcpc.__file__)]
    tool_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in tool_paths}
    cache = dc.Cache(args.cache,allow_x1_analysis=args.experimental_x1_plan)
    family=cache.validate_family() if args.experimental_x1_plan else None
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
    init(args.cache, ranges, targets, args.work,args.experimental_x1_plan)
    if args.experimental_x1_plan:summary['known_noreturn_exports']=STATE['noreturn_exports']

    def run(jobs, label):
        results, reached = {}, {}
        with multiprocessing.Pool(args.jobs, initializer=init,
                                  initargs=(args.cache, ranges, targets, args.work,args.experimental_x1_plan)) as pool:
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
    # Recognize narrowly structured x1 detached thunks from proven inbound
    # branches. Mapping flags0 do not make every TEXT-tail byte code.
    detached=[]
    if args.experimental_x1_plan:
        coverage=STATE['coverage'];covered=[]
        for address in sorted(inbound):
            if coverage.known(address) or any(lo<=address<hi for lo,hi in covered):continue
            first=coverage.detached_stub(address)
            if first is None:continue
            low,high=address,address+16
            # Batch adjacent structurally identical slots to avoid per-stub
            # decoder subprocesses. Only proven inbound roots are walked.
            while coverage.detached_stub(low-16) is not None:low-=16
            while coverage.detached_stub(high) is not None:high+=16
            index,offset,room=cache.locate(low)
            if room<high-low:raise ValueError('detached thunk pool crosses mapping')
            covered.append((low,high));detached.append((low,high,index,offset))
        islands+=detached
        # Every image can now transfer to a structurally owned detached pool.
        STATE['coverage']=dc.Coverage(ranges+[(lo,hi) for lo,hi,_,_ in detached],cache,allow_detached_stubs=True,noreturn_exports=STATE['noreturn_exports'].values())
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
    if args.experimental_x1_plan:
        originals=[dict(name=f.path.name,sha256=hashlib.sha256(f.data).hexdigest()) for f in cache.files]
        if tool_hashes!={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in tool_paths}:
            raise ValueError('proof tool source changed during run; results cannot qualify conversion')
        isa_counts=Counter();anomaly_counts=Counter();mnemonics=Counter()
        for entry in list(summary['images'].values())+island_results:
            isa_counts.update(entry.get('x1_isa',{}).get('remaining_counts',{}))
            anomaly_counts.update(entry.get('anomalies',{}))
            mnemonics.update(entry.get('x1_isa',{}).get('mnemonics',{}))
        summary.update(experimental_profile=x1.PROFILE,plan_only=True,boot_qualified=False,
                       family_validation=family,detached_thunk_pools=[dict(address=hex(lo),size=hi-lo,file=i,offset=o) for lo,hi,i,o in detached],remaining_isa_counts=dict(isa_counts),
                       anomaly_counts=dict(anomaly_counts),remaining_mnemonics=dict(mnemonics),complete_image_set=len(order)==len(images),
                       original_files=originals,original_file_manifest_sha256=hashlib.sha256(json.dumps(originals,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                       empty_images=[im.path for im in images if not im.instruction_sections()],
                       tool_hashes=tool_hashes)
    (args.work / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps(summary['totals'], indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
