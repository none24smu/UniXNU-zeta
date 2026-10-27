#!/usr/bin/env python3
"""Build an isolated real AIR->NIR->Mesa25 Zink SPIR-V feasibility bridge.

Reuses an existing pinned Mesa host build's NIR/utility archives. Never edits the
Mesa checkout, Gallium compiler/backend, selected frontend or device profiles.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import subprocess
import tarfile
import time

ROOT=Path(__file__).resolve().parent
ARCHIVE_SHA='592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(command,**kwargs):return subprocess.run(list(map(str,command)),check=True,**kwargs)
def limits():
    resource.setrlimit(resource.RLIMIT_AS,(500*1024*1024,500*1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mesa',type=Path,required=True)
    p.add_argument('--mesa-archive',type=Path,required=True)
    p.add_argument('--host-build',type=Path,required=True)
    p.add_argument('--candidate-source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();mesa=a.mesa.resolve();build=a.host_build.resolve();candidate=a.candidate_source.resolve();out=a.output.resolve()
    if out.exists():raise ValueError('preserve evidence: output must be a new directory')
    if sha(a.mesa_archive)!=ARCHIVE_SHA:raise ValueError('pinned Mesa25.0.7 archive SHA mismatch')
    critical=[mesa/'src/gallium/drivers/zink/nir_to_spirv/nir_to_spirv.c',mesa/'src/gallium/drivers/zink/nir_to_spirv/spirv_builder.c',mesa/'src/gallium/drivers/zink/nir_to_spirv/nir_to_spirv.h',mesa/'src/gallium/drivers/zink/nir_to_spirv/spirv_builder.h',mesa/'src/gallium/drivers/zink/zink_types.h',mesa/'src/gallium/drivers/zink/zink_compiler.h',mesa/'src/gallium/drivers/zink/zink_shader_keys.h',mesa/'src/vulkan/registry/vk.xml',*(mesa/'src/gallium/drivers/zink').glob('*.py'),*(mesa/'src/vulkan/util').glob('*.py')]
    wanted={'mesa-25.0.7/'+str(file.relative_to(mesa)):file for file in critical}
    # One sequential decompression. Random extractfile() against .xz would
    # repeatedly decompress the archive for every independently checked header.
    with tarfile.open(a.mesa_archive,mode='r|xz') as archive:
        for member in archive:
            if member.name not in wanted:continue
            file=wanted.pop(member.name)
            if archive.extractfile(member).read()!=file.read_bytes():
                raise ValueError('serializer/generator input differs from pinned archive: '+str(file))
    if wanted:raise ValueError('pinned archive lacks requested source inputs')
    provenance=json.loads((candidate/'duo-air-inputs.json').read_text())
    for name,digest in provenance['candidate_sha256'].items():
        if sha(candidate/name)!=digest:raise ValueError('AIR candidate source differs from prepared pin: '+name)
    out.mkdir(parents=True);gen=out/'generated';gen.mkdir();xml=mesa/'src/vulkan/registry/vk.xml';records=[]
    generators=[['python3',mesa/'src/gallium/drivers/zink/zink_device_info.py',gen/'zink_device_info.h',gen/'zink_device_info.c',xml],['python3',mesa/'src/gallium/drivers/zink/zink_instance.py',gen/'zink_instance.h',gen/'zink_instance.c',xml],['python3',mesa/'src/vulkan/util/vk_dispatch_table_gen.py','--xml',xml,'--out-h',gen/'vk_dispatch_table.h','--out-c',gen/'vk_dispatch_table.c','--beta','false'],['python3',mesa/'src/vulkan/util/vk_struct_type_cast_gen.py','--xml',xml,'--outdir',gen,'--beta','false'],['python3',mesa/'src/vulkan/util/vk_extensions_gen.py','--xml',xml,'--out-c',gen/'vk_extensions.c','--out-h',gen/'vk_extensions.h']]
    for command in generators:run(command)
    # Compile a fresh isolated AIR archive using the same pinned existing host
    # objects as the already tested candidate, rather than silently using donor AIR.
    run(['python3',ROOT/'build-air-candidate-host.py','--host-build',build,'--source',candidate,'--output',out/'candidate-host'])
    commands=json.loads(subprocess.check_output(['ninja','-C',str(build),'-t','compdb','c_COMPILER'],text=True));entry=next(x for x in commands if x['file'].endswith('/air_to_nir.c'));raw=shlex.split(entry['command']);flags=[];i=0
    while i<len(raw):
        if raw[i] in ('-o','-c','-MQ','-MF'):i+=2
        elif raw[i]=='-MD':i+=1
        else:flags.append(raw[i]);i+=1
    extra=['-I'+str(path) for path in (gen,candidate,mesa/'src/gallium/drivers/zink',mesa/'src/gallium/drivers/zink/nir_to_spirv',mesa/'src/gallium/include',mesa/'src/gallium/auxiliary',mesa/'src/vulkan/util',mesa/'src/mesa')]
    environment={**os.environ,'CCACHE_DISABLE':'1'}
    sources=[critical[0],critical[1],ROOT/'src/air-to-spirv-probe.c']
    for source in sources:
        command=[*flags,*extra,'-c',str(source),'-o',str(out/(source.name+'.o'))];result=run(command,cwd=build,env=environment,capture_output=True,text=True);records.append(command);(out/(source.name+'.log')).write_text(result.stdout+result.stderr)
    air_metadata=json.loads((out/'candidate-host/build.json').read_text());link=air_metadata['commands'][0];link[link.index('-o')+1]=str(out/'air-to-spirv-probe');link[link.index('src/compiler/air/air2nir.p/air2nir.c.o')]=str(out/'air-to-spirv-probe.c.o');link += [str(out/'nir_to_spirv.c.o'),str(out/'spirv_builder.c.o')];run(link,cwd=build)
    report={'scope':'owned resource-free AIR->real NIR->unmodified Zink SPIR-V; no native GPU/MTL proof','mesa_archive_sha256':ARCHIVE_SHA,'serializer_and_generator_sha256':{str(path.relative_to(mesa)):sha(path) for path in critical},'candidate_inputs':provenance,'nir_archive_sha256':sha(build/'src/compiler/nir/libnir.a'),'compiler_archive_sha256':sha(build/'src/compiler/libcompiler.a'),'air_archive_sha256':sha(out/'candidate-host/libair.a'),'compile_commands':records,'link_command':link,'tool_sha256':sha(out/'air-to-spirv-probe'),'tests':[],'passed':False}
    fixtures=json.loads((ROOT/'fixtures/duo_air_spirv_owned.json').read_text())
    for kind,name in [('triangle','duo_triangle_vertex'),('solid','duo_solid_fragment')]:
        started=time.monotonic();output=out/(kind+'.spv');command=['/usr/bin/time','-f','%e %M','-o',str(out/(kind+'.time')),str(out/'air-to-spirv-probe'),str(ROOT/'fixtures'/(name+'.bc')),str(output)];result=run(command,capture_output=True,text=True,timeout=20,preexec_fn=limits);elapsed=time.monotonic()-started
        validator=run(['spirv-val','--target-env','vulkan1.2',output],capture_output=True,text=True,timeout=max(0.1,20-elapsed),preexec_fn=limits)
        (out/(kind+'.log')).write_text(result.stdout+result.stderr);(out/(kind+'-validation.log')).write_text(validator.stdout+validator.stderr)
        if sha(output)!=fixtures['stages'][kind]['spirv_sha256']:raise ValueError('owned SPIR-V differs from embedded validated fixture')
        wall,rss=(out/(kind+'.time')).read_text().split();report['tests'].append({'stage':kind,'spirv_sha256':sha(output),'spirv_words':output.stat().st_size//4,'spirv_val_target':'vulkan1.2','translation_seconds':float(wall),'translation_max_rss_kib':int(rss),'translation_and_validation_seconds':time.monotonic()-started,'worker_address_space_limit_mib':500,'combined_wall_ceiling_seconds':20})
    refused=out/'refused-sampler.spv';result=subprocess.run([str(out/'air-to-spirv-probe'),str(ROOT/'fixtures/duo_sampler_fragment.bc'),str(refused)],capture_output=True,text=True,timeout=20,preexec_fn=limits)
    if result.returncode==0 or refused.exists() or 'REFUSE:' not in result.stderr:raise ValueError('resource/sampler negative control did not refuse before output')
    report['resource_refusal_verified']=True;report['passed']=True;(out/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: actual AIR->NIR->SPIR-V, two owned Vulkan1.2-valid modules; resource refusal; Gallium unchanged')
if __name__=='__main__':main()
