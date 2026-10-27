#!/usr/bin/env python3
"""Emit only two exact iOS27 FIRST-EXEC DIAGNOSTIC images, never an OS release.

All proven pointer/CSSC-single-word edits use existing verified selectors.
Unsupported retained instructions remain byte-for-byte and may fault. The
ordinary validated-contract converter remains closed; this is a distinct,
explicitly requested native experiment with an exact diagnostic kernel binding.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

from normalize_zeta_native_common import record,require

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('first_exec_rewriter',HERE/'rewrite-zeta-userland.py')
writer=importlib.util.module_from_spec(spec);spec.loader.exec_module(writer)
INPUTS={
 'sbin/launchd':('2b491c063b5d970071a014f310ff0e2579f8b28e13cdee8fc528d45298be5981','9751abae46906cf950fe1eb9f98f23e02817e109'),
 'usr/lib/dyld':('0c704ec68f828402c54cc732b8fc98136e1bc598d194875982d0ea65da94dd03','84427d341b4d76fc201999ba3a6cb1973a73673e'),
}


def candidate(original,path,trusted):
    require(path in INPUTS,'first-exec profile admits only exact launchd and dyld')
    expected,expected_cdhash=INPUTS[path]
    require(hashlib.sha256(original).hexdigest()==expected,'first-exec input fingerprint mismatch: '+path)
    info=writer.parse(original,allow_x1_analysis=True)
    require(info['architecture']=='arm64e.x1','first-exec source architecture mismatch')
    directory=writer.code_directory(original,info);writer.verify_code_pages(original,directory)
    old=writer.cdhash(original,directory)
    require(old.hex()==expected_cdhash and old in trusted,'original signature/trust membership mismatch')
    edits,proof=writer.lower(original,info,experimental_x1=True)
    require(not proof['anomalies'],'first-exec image has unresolved code boundaries')
    # lower() rejects every unproven pointer candidate, data-in-code edit, and
    # unsupported lowering. No broad rewrite/NOP mode is enabled here.
    data,report=writer.apply_proven_edits(original,info,directory,edits,proof)
    for site in proof.get('x1_isa',{}).get('remaining_sites',[]):
        off=site['fileoff']
        require(data[off:off+4]==original[off:off+4],'remaining ISA instruction was modified')
    attributes=trusted[old]
    report.update(schema='zeta-x1-first-exec-image-diagnostic-v1',qualification='FIRST-EXEC DIAGNOSTIC ONLY',
                  input_sha256=expected,output_sha256=hashlib.sha256(data).hexdigest(),
                  executable_output_written=True,boot_qualified=False,whole_cache_qualified=False,
                  whole_os_qualified=False,retained_unsupported_isa_unchanged=True,
                  effective_cpta='off',apple_cpta_on_checks_preserved=False,
                  trust_cache_entry={'cdhash':report['cdhash'],'hash_type':attributes[0],'flags':attributes[1],
                                     'constraint_category':attributes[2],'copied_from_original':True})
    return data,report,bytes.fromhex(report['cdhash'])+attributes


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-root',required=True,type=Path)
    parser.add_argument('--apple-trust-cache',required=True,action='append',type=Path)
    parser.add_argument('--diagnostic-kernel',required=True,type=Path)
    parser.add_argument('--native-checkpoint',required=True,type=Path)
    parser.add_argument('--source-manifest',required=True,type=Path)
    parser.add_argument('--kernel-rebind',type=Path,help='explicit unchanged-source/archive/linked-code receipt for a new diagnostic kernel')
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--emit-first-exec-diagnostic',action='store_true')
    args=parser.parse_args()
    require(args.emit_first_exec_diagnostic,'explicit --emit-first-exec-diagnostic is required')
    require(not args.output.exists(),'preserve existing diagnostic output')
    checkpoint=json.loads(args.native_checkpoint.read_text());source=json.loads(args.source_manifest.read_text())
    kernel=record(args.diagnostic_kernel)
    require(checkpoint['schema']=='zeta-x1-native-js-gcs-checkpoint-v1' and checkpoint['conversion_qualified'] is False,'expected separate native diagnostic checkpoint')
    require(checkpoint['kernel']['sha256']==source['sealed_kernel']['sha256'],'prior kernel/source/checkpoint identity mismatch')
    if kernel['sha256']!=checkpoint['kernel']['sha256']:
        require(args.kernel_rebind is not None,'new diagnostic kernel requires explicit CPU source/code rebind receipt')
    rebind=None
    if args.kernel_rebind:
        rebind=json.loads(args.kernel_rebind.read_text())
        require(rebind.get('schema')=='zeta-x1-first-exec-kernel-rebind-v1' and rebind['kernel']['sha256']==kernel['sha256'],'new kernel rebind identity mismatch')
        require(rebind.get('unchanged_cpu_sources') is True and rebind.get('linked_object_code_provenance_passed') is True and rebind.get('new_kernel_native_execution_verified') is False,'new kernel build/code proof incomplete or falsely runtime-qualified')
        require(rebind['reference_checkpoint']['sha256']==record(args.native_checkpoint)['sha256'] and rebind['reference_source_manifest']['sha256']==record(args.source_manifest)['sha256'],'new kernel rebind prior evidence mismatch')
        for item in [rebind['archive'],rebind['build_report'],rebind['compile_commands']]+[unit['object'] for unit in rebind['units'].values()]:
            require(record(item['path'])['sha256']==item['sha256'],'rebound CPU build artifact changed')
    require(checkpoint['gcs_feature_absent_all_eight_online_guest_cpus'] is True and checkpoint['js_default_fpcr_boot_policy_scope_passed'] is True,'diagnostic JS/GCS evidence incomplete')
    require(checkpoint['source_manifest']['sha256']==hashlib.sha256(args.source_manifest.read_bytes()).hexdigest(),'source manifest not bound to checkpoint')
    trusted={}
    for path in args.apple_trust_cache:
        _,raw=writer.im4p_payload(path.read_bytes());trusted.update(writer.trust_cache_entries(raw))
    prepared=[];entries=[]
    for name in INPUTS:
        original=(args.input_root/name).read_bytes();data,report,entry=candidate(original,name,trusted)
        require(len(data)==len(original),'first-exec replacement changes original file length')
        report.update(input={'path':str((args.input_root/name).resolve()),'sha256':hashlib.sha256(original).hexdigest(),'bytes':len(original)},
                      output_bytes=len(data),source_and_output_lengths_equal=True)
        prepared.append((name,data,report));entries.append(entry)
    # Validate everything before creating reviewable outputs; no source root is
    # mutated. A separate staging step must match this exact kernel identity.
    args.output.mkdir(parents=True)
    reports={}
    for name,data,report in prepared:
        path=args.output/'root'/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data);path.chmod(0o755);reports[name]=report
        (args.output/(Path(name).name+'.report.json')).write_text(json.dumps(report,indent=2)+'\n')
    entries=sorted(set(entries));payload=b''.join(entries)
    trust=struct.pack('<I16sI',2,hashlib.sha256(payload).digest()[:16],len(entries))+payload
    (args.output/'first-exec.trustcache').write_bytes(trust)
    metadata={'schema':'zeta-x1-first-exec-diagnostic-v1','qualification':'FIRST-EXEC DIAGNOSTIC ONLY',
              'kernel':kernel,'native_checkpoint':record(args.native_checkpoint),'source_manifest':record(args.source_manifest),
              'kernel_rebind':record(args.kernel_rebind) if args.kernel_rebind else None,
              'prior_native_js_gcs_kernel_sha256':checkpoint['kernel']['sha256'],
              'new_kernel_native_execution_verified':False,
              'tools':{p.name:record(p) for p in [Path(__file__),HERE/'rewrite-zeta-userland.py',HERE/'zeta_x1_compat.py',HERE/'zeta_userland_code.py',HERE/'zeta_userland_pauth.py',HERE/'normalize_zeta_native_common.py',HERE/'rebind-zeta-first-exec-kernel.py']},
              'images':reports,'trust_cache':record(args.output/'first-exec.trustcache'),
              'required_boot_arguments':['zeta-cssc-compat=2','zeta-js-compat=2'],
              'kernel_cssc_positive_scope_on_this_exact_kernel_qualified':False,
              'boot_qualified':False,'shared_cache_rewritten':False,'whole_os_qualified':False,
              'next_markers':['XNU first EL0 PC equals dyld entry plus slide','dyld instruction at original VA0x3b8c is lowered NOP',
                              'Capture first unhandled EL0 PC/opcode/LR and image mapping; retain original word and report offset',
                              'Loading the original shared cache may fault on its first unconverted PAC/PAuthLR instruction'],
              'limits':['Two exact standalone image candidates only; original stock cache remains unsupported',
                        'Optional TPRO/MTE/SHA512 and other unsupported instructions are retained verbatim, not declared globally unreachable',
                        'Current native Apple-vector/feature evidence is iOS26 diagnostic evidence; initial iOS27 stack must be captured',
                        'CSSC native qualification is on a separate older kernel; current source/host evidence does not silently become native proof',
                        'CPTA OFF is the explicit ordinary-pointer experiment and does not preserve Apple poison checks',
                        'No root image, kernel build, phone operation or persistent partition change is performed']}
    (args.output/'manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps({'output':str(args.output),'image_edits':{n:r['instruction_edits'] for n,r in reports.items()},'boot_qualified':False},indent=2))


if __name__=='__main__':main()
