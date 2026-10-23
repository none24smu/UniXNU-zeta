#!/usr/bin/env python3
"""Find instruction words in a dyld shared cache that the SM8350 cores cannot run.

Kryo 680 (Cortex-X1, A78, A55) implements Armv8.2-A with LSE, RDM, FP16,
dot product, RCpc and DC CVAP: what Linux reports as fp asimd aes pmull sha1
sha2 crc32 atomics fphp asimdhp asimdrdm lrcpc dcpop asimddp. Every unique
32-bit word in the cache's instruction sections is disassembled twice by
llvm-mc: with every A-profile feature, and with only the SM8350 set. A word
the first decodes as an instruction the second does not (rejected, or seen
only as a generic system access such as SB as msr) needs a feature these
cores lack; a word the second sees as a hint runs as a NOP and is not
counted. Two classes
llvm-mc decodes either way are counted by encoding: EL0 accesses to
implementation-defined system registers (op0 3, CRn 15) and Apple AMX
words (0x00201000-0x00201fff, permanently undefined elsewhere).

Words are counted by linear sweep, so table data that happens to decode is
included; the report lists, per mnemonic, how many words and which images
hold them. Reads the cache only.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import subprocess
import sys

import numpy as np

import zeta_dyld_cache as dc

FULL = ('+v9.5a,+sve2,+sve2-aes,+sve2-sha3,+sve2-sm4,+sve2-bitperm,+sme2p1,+sme-f64f64,+sme-i16i64,+bf16,+i8mm,'
        '+mops,+cssc,+sha3,+sm4,+fp16fml,+rcpc3,+lse128,+the,+d128,+gcs,+ite,+lut,+faminmax,+fp8,+jsconv,+complxnum,'
        '+rand,+mte,+ls64,+wfxt,+hbc,+flagm,+altnzcv,+pauth,+predres,+sb,+specrestrict,+ssbs,+tme')
SM8350 = '+v8a,+fp-armv8,+neon,+aes,+sha2,+crc,+lse,+fullfp16,+rdm,+rcpc,+ccpp,+dotprod,+ras'


def disassemble(words, features):
    """{word: mnemonic or None} from llvm-mc --disassemble with the given features."""
    text = ''.join(f'0x{w & 0xff:02x} 0x{(w >> 8) & 0xff:02x} 0x{(w >> 16) & 0xff:02x} 0x{w >> 24:02x}\n'
                   for w in words)
    result = subprocess.run(['llvm-mc', '--disassemble', '-triple=aarch64', f'-mattr={features}'],
                            input=text, capture_output=True, text=True)
    invalid = {int(m.group(1)) for m in re.finditer(r'<stdin>:(\d+):\d+: warning: invalid instruction encoding',
                                                   result.stderr)}
    mnemonics = [line.split()[0] for line in result.stdout.splitlines()
                 if line.startswith('\t') and not line.lstrip().startswith('.')]
    found, valid = {}, iter(mnemonics)
    for line, word in enumerate(words, 1):
        found[word] = None if line in invalid else next(valid, '?')
    return found


def section_words(cache):
    """(image path, words) for every instruction section of every image."""
    for address, path in cache.images:
        for section in dc.Image(cache, address, path).instruction_sections():
            yield path, np.frombuffer(cache.files[section['file']].data, dtype='<u4', count=section['size'] // 4,
                                      offset=section['offset'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    cache = dc.Cache(args.cache)
    words, pending = np.zeros(0, dtype=np.uint32), []
    for _, data in section_words(cache):
        pending.append(np.unique(data))
        if sum(len(part) for part in pending) > 1 << 24:
            words, pending = np.unique(np.concatenate([words] + pending)), []
    words = np.unique(np.concatenate([words] + pending))
    print(f'{len(words)} unique words', file=sys.stderr, flush=True)
    flagged = {}
    for start in range(0, len(words), 1 << 20):
        batch = words[start:start + (1 << 20)].tolist()
        full, restricted = disassemble(batch, FULL), disassemble(batch, SM8350)
        flagged.update({word: full[word] for word in batch
                        if full[word] and full[word] != restricted[word] and restricted[word] != 'hint'})
        print(f'{start + len(batch)}/{len(words)}', file=sys.stderr, flush=True)
    keys = np.array(sorted(flagged), dtype=np.uint32)
    needs = defaultdict(lambda: dict(words=set(), occurrences=0, images=Counter()))
    special = defaultdict(Counter)
    for path, data in section_words(cache):
        hits = data[np.isin(data, keys)]
        for word, count in zip(*np.unique(hits, return_counts=True)):
            entry = needs[flagged[int(word)]]
            entry['words'].add(int(word))
            entry['occurrences'] += int(count)
            entry['images'][path] += int(count)
        impdef = ((data & np.uint32(0xffd0f000)) == np.uint32(0xd510f000)) & (((data >> np.uint32(19)) & np.uint32(1)) == 1)
        amx = (data & np.uint32(0xfffff000)) == np.uint32(0x00201000)
        if impdef.any():
            special['impdef_sysreg'][path] += int(impdef.sum())
        if amx.any():
            special['amx'][path] += int(amx.sum())
    report = dict(schema='zeta-cpu-feature-audit-v1', cache=str(args.cache), unique_words=len(words),
                  sm8350_features=SM8350,
                  unsupported_mnemonics={m: dict(words=len(e['words']), occurrences=e['occurrences'],
                                                 image_count=len(e['images']), images=dict(e['images'].most_common(12)),
                                                 examples=[hex(w) for w in sorted(e['words'])[:6]])
                                         for m, e in sorted(needs.items(), key=lambda kv: -kv[1]['occurrences'])},
                  impdef_sysreg=dict(occurrences=sum(special['impdef_sysreg'].values()),
                                     images=dict(special['impdef_sysreg'].most_common(20))),
                  amx=dict(occurrences=sum(special['amx'].values()), images=dict(special['amx'].most_common(20))))
    args.report.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({m: e['occurrences'] for m, e in report['unsupported_mnemonics'].items()}))
    print(json.dumps(dict(impdef=report['impdef_sysreg']['occurrences'], amx=report['amx']['occurrences'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
