#!/usr/bin/env python3
"""Bind a new diagnostic kernel to unchanged CPU source and linked objects.

This is build/code provenance, never native execution qualification. The e071
native checkpoint remains prior evidence for its own kernel only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from normalize_zeta_native_common import record,require,mach_window

UNITS={
 'ZetaUserInstructionCompat':['_ZetaUserInstructionCompatEmulate'],
 'ZetaUserInstructionKernel':['_zeta_user_instruction_compat'],
 'ZetaJsConvert':['_ZetaJsConvert'],
 'ZetaJsInstructionKernel':['_zeta_js_instruction_compat'],
 'ZetaJsUserFpState':['_zeta_js_user_neon_snapshot'],
}
HEADERS=['ZetaUserInstructionCompat.h','ZetaJsConvert.h','ZetaJsUserFpState.h']


def object_functions(data,names):
    require(struct.unpack_from('<4I',data)==(0xfeedfacf,0x100000c,0,1),'CPU build output is not a plain ARM64 Mach-O object')
    sections=[];symtab=None;at=32
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        command,size=struct.unpack_from('<II',data,at);require(size>=8 and at+size<=len(data),'object command range')
        if command==0x19:
            count=struct.unpack_from('<I',data,at+64)[0]
            for i in range(count):
                pos=at+72+i*80;address,length,offset,align,reloff,nreloc,flags=struct.unpack_from('<QQ5I',data,pos+32)
                sections.append({'addr':address,'size':length,'offset':offset,'reloff':reloff,'nreloc':nreloc,'flags':flags})
        if command==2:symtab=struct.unpack_from('<4I',data,at+8)
        at+=size
    require(symtab is not None,'CPU object lacks symbol table')
    symoff,count,stroff,strsize=symtab;symbols=[]
    for i in range(count):
        string,kind,section,desc,value=struct.unpack_from('<IBBHQ',data,symoff+i*16)
        if kind&0xe==0xe and section:
            require(string<strsize and 0<section<=len(sections),'object symbol bounds')
            stop=data.find(b'\0',stroff+string,stroff+strsize);require(stop>=0,'object symbol terminator')
            symbols.append((data[stroff+string:stop].decode(),section,value))
    result={}
    for name in names:
        matches=[s for s in symbols if s[0]==name];require(len(matches)==1,'missing/duplicate CPU object function '+name)
        _,number,begin=matches[0];s=sections[number-1]
        require(s['flags']&0x80000400,'CPU symbol is not declared instruction text')
        end=min([v for _,n,v in symbols if n==number and v>begin]+[s['addr']+s['size']])
        length=end-begin;require(4<=length<=16384 and not(length&3),'CPU function span bounds')
        offset=s['offset']+begin-s['addr'];body=data[offset:offset+length];require(len(body)==length,'CPU text file bounds')
        ignored=set()
        for i in range(s['nreloc']):
            address,bits=struct.unpack_from('<II',data,s['reloff']+i*8)
            require(not address&(1<<31),'scattered/negative ARM64 relocation unsupported')
            width=1<<((bits>>25)&3)
            require(width in (4,8),'unexpected ARM64 code relocation width')
            pc=s['addr']+address
            if begin<=pc<end:
                require(pc+width<=end,'CPU relocation crosses function boundary')
                ignored.update(range(pc-begin,pc-begin+width))
        require(len(ignored)<length,'CPU function is entirely relocation bytes')
        result[name]={'object_address':begin,'bytes':body,'relocation_byte_offsets':sorted(ignored)}
    return result


def compare_function(source,linked):
    require(len(source['bytes'])==len(linked),'linked CPU function size mismatch')
    ignored=set(source['relocation_byte_offsets'])
    require(all(a==b for i,(a,b) in enumerate(zip(source['bytes'],linked)) if i not in ignored),'linked CPU function differs outside declared object relocations')
    return len(linked)-len(ignored)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',required=True,type=Path);p.add_argument('--cpu-build',required=True,type=Path)
    p.add_argument('--reference-checkpoint',required=True,type=Path);p.add_argument('--reference-source-manifest',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path);args=p.parse_args()
    require(not args.output.exists(),'preserve existing rebind output')
    reference=json.loads(args.reference_checkpoint.read_text());source=json.loads(args.reference_source_manifest.read_text())
    require(reference['schema']=='zeta-x1-native-js-gcs-checkpoint-v1' and reference['conversion_qualified'] is False,'prior diagnostic reference required')
    require(reference['source_manifest']['sha256']==record(args.reference_source_manifest)['sha256'],'prior source manifest mismatch')
    report=json.loads((args.cpu_build/'build-report.json').read_text());commands=json.loads((args.cpu_build/'compile-command.json').read_text())
    require(report['js_compat_compiled'] is True,'new CPU archive lacks JS integration')
    for name in [u+'.c' for u in UNITS]+HEADERS:
        expected=source['sources']['board/package/'+name]
        require(record(expected['path'])['sha256']==expected['sha256'],'reference source snapshot changed')
        require(report['sources'].get(name)==expected['sha256'],'CPU source changed from native reference: '+name)
    archive=args.cpu_build/'libBootProgress.a';require(record(archive)['sha256']==report['archive_sha256'],'new CPU archive hash mismatch')
    members=subprocess.check_output(['llvm-ar','t',str(archive)],text=True).splitlines()
    symbols={}
    for line in subprocess.check_output(['llvm-nm','--defined-only',str(args.kernel)],text=True).splitlines():
        fields=line.split()
        if len(fields)==3:
            try:symbols[fields[-1]]=int(fields[0],16)
            except ValueError:pass
    kernel=args.kernel.read_bytes();units={}
    for unit,names in UNITS.items():
        member=unit+'.o';require(members.count(member)==1,'CPU archive missing/duplicate object '+unit)
        raw=subprocess.check_output(['llvm-ar','p',str(archive),member])
        require(raw==(args.cpu_build/member).read_bytes(),'CPU archive/object file mismatch '+unit)
        command=commands.get(unit,[])
        require('-mgeneral-regs-only' in command and any(str(a).endswith('/'+unit+'.c') for a in command),'CPU compile record missing exact unit/general-register policy')
        if unit=='ZetaUserInstructionKernel':require('-DZETA_KERNEL_JS_EMULATION=1' in command,'CSSC object lacks JS dispatch define')
        matches={}
        for name,body in object_functions(raw,names).items():
            require(name in symbols,'new kernel lacks CPU function '+name)
            linked=mach_window(kernel,symbols[name],len(body['bytes']));compared=compare_function(body,linked)
            matches[name]={'va':hex(symbols[name]),'bytes':len(linked),'compared_nonrelocation_bytes':compared,
                           'object_relocation_byte_offsets':body['relocation_byte_offsets'],'linked_sha256':hashlib.sha256(linked).hexdigest()}
        units[unit]={'object':record(args.cpu_build/member),'functions':matches,'compile_command':command}
    value={'schema':'zeta-x1-first-exec-kernel-rebind-v1','kernel':record(args.kernel),
           'reference_checkpoint':record(args.reference_checkpoint),'reference_source_manifest':record(args.reference_source_manifest),
           'build_report':record(args.cpu_build/'build-report.json'),'compile_commands':record(args.cpu_build/'compile-command.json'),
           'archive':record(archive),'units':units,'unchanged_cpu_sources':True,'linked_object_code_provenance_passed':True,
           'new_kernel_native_execution_verified':False,'conversion_qualified':False,
           'limits':['Source/archive/linked-code proof only; branch/address relocations are identified from actual Mach-O relocation records',
                     'Prior native CSSC and JS/GCS evidence retain their own distinct kernel identities',
                     'No new kernel, phone access or broad optional-framework audit is performed']}
    args.output.write_text(json.dumps(value,indent=2)+'\n');print(args.output)


if __name__=='__main__':main()
