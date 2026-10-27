#!/usr/bin/env python3
"""Build owned hand-written AIR 2.9 pixel-test inputs; these are not Apple compositor shaders."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

LAYOUT = 'e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v16:16:16-v24:32:32-v32:32:32-v48:64:64-v64:64:64-v96:128:128-v128:128:128-v192:256:256-v256:256:256-v512:512:512-v1024:1024:1024-n8:16:32'


def llvm(name, stage, parameters, body, inputs, nodes, globals=''):
    output = '!"air.position"' if stage == 'vertex' else '!"air.render_target", i32 0, i32 0'
    return f'''source_filename = "{name}"
target datalayout = "{LAYOUT}"
target triple = "air64-apple-ios27.1.0"
{globals}
define <{{ <4 x float> }}> @{name}({parameters}) {{
{body}
}}
!air.version = !{{!0}}
!air.language_version = !{{!1}}
!air.{stage} = !{{!2}}
!0 = !{{i32 2, i32 9, i32 0}}
!1 = !{{!"Metal", i32 4, i32 1, i32 0}}
!2 = !{{ptr @{name}, !3, !5}}
!3 = !{{!4}}
!4 = !{{{output}, !"air.arg_type_name", !"float4", !"air.arg_name", !"out"}}
!5 = !{{{inputs}}}
{nodes}
'''


def sources():
    vertex = llvm('duo_triangle_vertex', 'vertex', 'i32 %id', '''  %one = icmp eq i32 %id, 1
  %two = icmp eq i32 %id, 2
  %x = select i1 %one, float 3.000000e+00, float -1.000000e+00
  %y = select i1 %two, float 3.000000e+00, float -1.000000e+00
  %v0 = insertelement <4 x float> undef, float %x, i32 0
  %v1 = insertelement <4 x float> %v0, float %y, i32 1
  %v2 = insertelement <4 x float> %v1, float 0.000000e+00, i32 2
  %v3 = insertelement <4 x float> %v2, float 1.000000e+00, i32 3
  %out = insertvalue <{ <4 x float> }> undef, <4 x float> %v3, 0
  ret <{ <4 x float> }> %out''', '!6',
        '!6 = !{i32 0, !"air.vertex_id", !"air.arg_type_name", !"uint", !"air.arg_name", !"id"}')
    solid = llvm('duo_solid_fragment', 'fragment', '', '''  %out = insertvalue <{ <4 x float> }> undef, <4 x float> <float 2.500000e-01, float 5.000000e-01, float 1.250000e-01, float 2.500000e-01>, 0
  ret <{ <4 x float> }> %out''', '', '')
    sampler = {}
    for name, second in [('duo_sampler_fragment', 0), ('duo_sampler_bias_fragment', 1)]:
        glob = f'''@__air_sampler_state = internal addrspace(2) constant [2 x i64] [i64 34901797601050697, i64 {second}], align 8
declare {{ <4 x float>, i8 }} @air.sample_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2), <2 x float>, i1, <2 x i32>, i1, float, float, i32)'''
        sampler[name] = llvm(name, 'fragment', 'ptr addrspace(1) %texture', '''  %sample = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %texture, ptr addrspace(2) @__air_sampler_state, <2 x float> <float 1.500000e+00, float 5.000000e-01>, i1 true, <2 x i32> zeroinitializer, i1 false, float 0.000000e+00, float 0.000000e+00, i32 0)
  %value = extractvalue { <4 x float>, i8 } %sample, 0
  %out = insertvalue <{ <4 x float> }> undef, <4 x float> %value, 0
  ret <{ <4 x float> }> %out''', '!6',
            '!6 = !{i32 0, !"air.texture", !"air.location_index", i32 0, i32 1, !"air.sample", !"air.arg_type_name", !"texture2d<float, sample>", !"air.arg_name", !"texture"}', glob)
    return {'duo_triangle_vertex': (0, vertex), 'duo_solid_fragment': (1, solid),
            **{name: (1, source) for name, source in sampler.items()}}


def tag(name, payload):
    return name.encode() + struct.pack('<H', len(payload)) + payload


def metallib(modules):
    entries = b''
    bitcode = b''
    for i, (name, kind, module) in enumerate(modules):
        tags = tag('NAME', name.encode() + b'\0') + tag('TYPE', bytes([kind]))
        tags += tag('HASH', hashlib.sha256(module).digest())
        tags += tag('OFFT', struct.pack('<3Q', i * 8, i * 8, len(bitcode)))
        tags += tag('VERS', struct.pack('<4H', 2, 9, 4, 1)) + tag('MDSZ', struct.pack('<Q', len(module))) + b'ENDT'
        entries += struct.pack('<I', len(tags) + 4) + tags
        bitcode += module
    public = private = (struct.pack('<I', 8) + b'ENDT') * len(modules)
    public_at = 88 + 4 + len(entries) + 26
    private_at = public_at + len(public)
    bitcode_at = private_at + len(private)
    linkage_at = bitcode_at + len(bitcode)
    linkage = tag('NAME', b'duo-air-probe.metallib\0') + b'ENDT'
    extended = tag('HDYN', struct.pack('<2Q', linkage_at, len(linkage))) + b'ENDT'
    body = struct.pack('<I', len(modules)) + entries + extended + public + private + bitcode + linkage
    header = b'MTLB' + struct.pack('<3H2B2H', 1, 2, 9, 0, 0x82, 27, 1) + struct.pack('<Q', 88 + len(body))
    header += struct.pack('<8Q', 88, len(entries), public_at, len(public), private_at, len(private), bitcode_at, len(bitcode))
    return header + body


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--llvm-as', default='llvm-as')
    a = p.parse_args(); a.output.mkdir(parents=True, exist_ok=True)
    modules = []
    for name, (kind, source) in sources().items():
        ll, bc = a.output / (name + '.ll'), a.output / (name + '.bc')
        ll.write_text(source)
        subprocess.run([a.llvm_as, str(ll), '-o', str(bc)], check=True)
        code = bc.read_bytes()
        if code[:4] == bytes.fromhex('dec0170b'):
            # llvm-as emits the wrapper itself for an AIR/Darwin target triple.
            wrapped = code
        elif code[:4] == b'BC\xc0\xde':
            wrapped = struct.pack('<5I', 0x0b17c0de, 0, 20, len(code), 0xffffffff) + code
        else:
            raise ValueError('assembler output is neither LLVM stream nor wrapper')
        wrapped += bytes((-len(wrapped)) % 16)
        modules.append((name, kind, wrapped))
    library = a.output / 'duo-air-probe.metallib'
    library.write_bytes(metallib(modules))
    manifest = {'scope': 'owned synthetic AIR shader gate; not Apple compositor output',
                'assembler': subprocess.check_output([a.llvm_as, '--version'], text=True).strip(),
                'files': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in a.output.iterdir() if path.suffix in ('.ll', '.bc', '.metallib')},
                'functions': [name for name, _, _ in modules]}
    (a.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('PASS: generated owned AIR2.9 vertex/solid/sampler and explicit bias-refusal fixtures')


if __name__ == '__main__': main()
