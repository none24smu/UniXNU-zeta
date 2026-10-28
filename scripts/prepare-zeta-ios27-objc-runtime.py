#!/usr/bin/env python3
"""Prepare the exact iOS27 ObjC trampoline owner-runtime diagnostic.

This admits one pinned original library and one proven branch lowering. It is
separate from the closed general x1 conversion gate. It writes a derived owner
signature and one owner trust-cache entry; it does not authenticate an Apple OS
root, install files, or establish that SpringBoard reaches the display.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('objc_runtime_writer', HERE / 'rewrite-zeta-userland.py')
writer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(writer)

SOURCE_SHA256 = 'ce6ad3551dcd442d0b2ab172d93a5323d5976746e62a8fea8fc4161185e5dcc1'
SOURCE_CDHASH = 'b09142aa85d1df413c3457d7111455d582857fae'


def candidate(original, trusted):
    writer.require(hashlib.sha256(original).hexdigest() == SOURCE_SHA256, 'ObjC runtime input fingerprint mismatch')
    info = writer.parse(original, allow_x1_analysis=True)
    writer.require(info['filetype'] == 6 and info['subtype'] == 0x8000000c, 'expected the pinned x1 dylib')
    directory = writer.code_directory(original, info)
    writer.verify_code_pages(original, directory)
    old_hash = writer.cdhash(original, directory)
    writer.require(old_hash.hex() == SOURCE_CDHASH and old_hash in trusted, 'original ObjC signature/trust membership mismatch')
    edits, proof = writer.lower(original, info, experimental_x1=True)
    writer.require(not proof['anomalies'] and not proof['x1_isa']['remaining_counts'], 'ObjC code proof is incomplete')
    writer.require(len(edits) == 1, 'unexpected ObjC instruction count')
    edit = edits[0]
    writer.require((edit['fileoff'], edit['original_word'], edit['ordinary_word'], edit['evidence']) ==
                   (0x4010, '0xd71f0a0f', '0xd61f0200', 'start'), 'unexpected ObjC instruction edit')
    data, report = writer.apply_proven_edits(original, info, directory, edits, proof)
    writer.require(len(data) == len(original) and struct.unpack_from('<I', data, 8)[0] == 0, 'owner runtime shape mismatch')
    attributes = trusted[old_hash]
    entry = bytes.fromhex(report['cdhash']) + attributes
    writer.require(len(entry) == 24, 'invalid copied trust-cache attributes')
    report.update(schema='zeta-ios27-objc-runtime-diagnostic-v1',
                  qualification='EXACT-INPUT OWNER RUNTIME DIAGNOSTIC ONLY',
                  input_sha256=SOURCE_SHA256, output_sha256=hashlib.sha256(data).hexdigest(),
                  output_bytes=len(data), original_trust_cache_attributes=list(attributes),
                  general_x1_conversion_qualified=False, whole_os_qualified=False,
                  native_execution_verified=False)
    return data, report, entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--apple-trust-cache', required=True, action='append', type=Path, help='original IM4P trust cache')
    parser.add_argument('--diagnostic-kernel', required=True, type=Path)
    parser.add_argument('--kernel-rebind', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--emit-exact-runtime-diagnostic', action='store_true')
    args = parser.parse_args()
    writer.require(args.emit_exact_runtime_diagnostic, 'explicit diagnostic opt-in is required')
    writer.require(not args.output.exists(), 'preserve existing diagnostic output')
    kernel = args.diagnostic_kernel.read_bytes()
    rebind = json.loads(args.kernel_rebind.read_text())
    writer.require(rebind.get('schema') == 'zeta-x1-first-exec-kernel-rebind-v1' and
                   rebind['kernel']['sha256'] == hashlib.sha256(kernel).hexdigest() and
                   rebind.get('unchanged_cpu_sources') is True and
                   rebind.get('linked_object_code_provenance_passed') is True,
                   'missing exact diagnostic kernel CPU source/code binding')
    trusted = {}
    for path in args.apple_trust_cache:
        _, raw = writer.im4p_payload(path.read_bytes())
        trusted.update(writer.trust_cache_entries(raw))
    data, report, entry = candidate(args.input.read_bytes(), trusted)
    report.update(kernel_sha256=hashlib.sha256(kernel).hexdigest(),
                  kernel_rebind_sha256=hashlib.sha256(args.kernel_rebind.read_bytes()).hexdigest())
    # All validation precedes output; installation remains a separate step.
    args.output.mkdir(parents=True)
    library = args.output / 'libobjc-trampolines.dylib'
    library.write_bytes(data)
    library.chmod(0o644)
    trust = struct.pack('<I', 2) + hashlib.sha256(entry).digest()[:16] + struct.pack('<I', 1) + entry
    (args.output / 'owner-runtime.trustcache').write_bytes(trust)
    (args.output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(cdhash=report['cdhash'], output_sha256=report['output_sha256'],
                          instruction_edits=report['instruction_edits']), indent=2))


if __name__ == '__main__':
    main()
