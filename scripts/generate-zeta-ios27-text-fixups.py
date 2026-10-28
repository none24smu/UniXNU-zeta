#!/usr/bin/env python3
"""Generate exact NUL ADT descriptors from eight retained original child plans.

Original signed files are never rewritten. Kernel/profile selection and device
tree integration are separate explicit actions.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

import zeta_x1_compat as x1
import zeta_userland_pauth as pauth
from normalize_zeta_native_common import record,require
from zeta_text_fixups import encode_table,parse_table,MAX_ENTRIES

HERE=Path(__file__).resolve().parent
EXPECTED={
 '/usr/libexec/xpcproxy':'fabd22f5efc9cc6f0ad676149c5b99641dee66b7e29fa7abf93082112312997b',
 '/usr/libexec/backboardd':'bade2cec2b463615ac141a2aaf11156757ef9f3118a9090c82eb6e3903258dfe',
 '/System/Library/CoreServices/SpringBoard.app/SpringBoard':'f83e407626a0273dcf302a8e290ff292c83427c631b0eba8c44855ab089a16bc',
 '/usr/sbin/notifyd':'fce2c8afd88c36985f667a0f73c163279d065385e1a018feb951d5b1aa98b370',
 '/usr/libexec/logd':'b84ce593b8218b77ee36d9e9a2117865df759785919bf9d6f02e7910bb89f705',
 '/usr/libexec/runningboardd':'5d59bd9f4d3ba09a043db186e7760b6073f5d5b2c6124447de7861eab8d4c442',
 '/usr/libexec/lsd':'fa979e82d4e545374de80c5eea6ba422435206c1cce10f68eb717eeccb88b97d',
 '/usr/libexec/securityd':'6d7627946413cca7639e7ccf53aa6947b18658fed1ee7d54ce330cf51ab80260',
}
EXPECTED_PLANS={
 'xpcproxy':'8beb5d23ad599483ebdbb46854eb3e844b929a49351125269d312e14e28f978b',
 'SpringBoard':'517146e1db3d5ddefb91dce60f75e49f380db30f54d330cfc4c362c4604b9d84',
 'backboardd':'e1e5cf25e0c5e02b47f87860001debb9cb00af8a70fe56f4c73e887b22d79c40',
 'logd':'62f0b398d4d910ad45f87ab97603e1be36d7540632f2d520621f1cbdb4e66cd2',
 'lsd':'5b62e0e393ab7e46d05ac7097a56d3a57e47748ce1bd2d1fe9f5f3031907e42e',
 'runningboardd':'7b3579a6582b45055424797d310d5c0b18f34ee953c776051dcdb61d117feda3',
 'securityd':'ac685327242d34a4edb0f60a22d180eb6f080461cff6b0c048d868376aa4dd2f',
 'notifyd':'9bdea7fd4303c68ee0d7cb6bf8f5222680836073d0920ec492e55b810c3d7771',
}


def grouped(name,edits):
    result=[]
    for offset,before,after in sorted(edits):
        if result and offset<result[-1][1]+len(result[-1][2]):raise ValueError('overlapping source instruction edits')
        if result and offset==result[-1][1]+len(result[-1][2]) and len(result[-1][2])+len(before)<=16 and offset//4096==result[-1][1]//4096:
            old=result.pop();result.append((name,old[1],old[2]+before,old[3]+after))
        else:result.append((name,offset,before,after))
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--child-checkpoint',required=True,type=Path);p.add_argument('--output',required=True,type=Path);args=p.parse_args()
    require(not args.output.exists(),'preserve existing descriptor output')
    spec=importlib.util.spec_from_file_location('fixup_original_reader',HERE/'rewrite-zeta-userland.py');writer=importlib.util.module_from_spec(spec);spec.loader.exec_module(writer)
    summary=json.loads((args.child_checkpoint/'summary.json').read_text());require({e['path'] for e in summary['originals']}==set(EXPECTED),'exact eight-child inventory required')
    records=[];files=[];total=0
    for item in summary['originals']:
        name=Path(item['path']).name;path=args.child_checkpoint/'originals'/item['path'].lstrip('/');raw=path.read_bytes()
        require(hashlib.sha256(raw).hexdigest()==EXPECTED[item['path']]==item['original_sha256'],'original child fingerprint mismatch')
        plan_path=args.child_checkpoint/(name+'.plan.json');plan_raw=plan_path.read_bytes()
        require(hashlib.sha256(plan_raw).hexdigest()==EXPECTED_PLANS[name],'frozen proven child plan fingerprint mismatch')
        plan=json.loads(plan_raw)
        require(plan['input_sha256']==EXPECTED[item['path']] and plan['executable_output_written'] is False and not plan['code_proof']['anomalies'],'plan identity/boundary failure')
        info=writer.parse(raw,allow_x1_analysis=True);directory=writer.code_directory(raw,info);writer.verify_code_pages(raw,directory)
        require(writer.cdhash(raw,directory).hex()==plan['original_cdhash'],'original signature/CDHash mismatch')
        sections=writer.instruction_sections(info);translate=writer.va_to_off(info);edits=[]
        for edit in plan['edits']:
            pc=int(edit['va'],16);offset=edit['fileoff'];before=int(edit['original_word'],16);after=int(edit['ordinary_word'],16)
            require(edit['evidence'] in ('unwind','pointer','landing','stub','call','start','gap'),'unproven edit evidence')
            require(any(s['addr']<=pc and pc+4<=s['addr']+s['size'] for s in sections) and translate(pc,4)==offset,'edit outside declared instruction/file range')
            require(not any(a<=offset<a+n for a,n,k in info['dice']),'edit overlaps data-in-code')
            require(offset+4<=directory['code_limit'] and struct.unpack_from('<I',raw,offset)[0]==before,'original instruction mismatch')
            lower=x1.lower_pointer_off(before,'off') or x1.lower_cssc_single(before) or pauth.lower(before)
            require(lower is not None and lower[1]==after and before!=after,'unsupported/unknown/identity edit')
            edits.append((offset,struct.pack('<I',before),struct.pack('<I',after)))
        groups=grouped(name,edits);records+=groups;total+=len(edits)
        files.append({'path':item['path'],'basename':name,'original':record(path),'original_cdhash':plan['original_cdhash'],'plan':record(plan_path),'instruction_edits':len(edits),'descriptors':len(groups),'retained_isa_unchanged':plan['code_proof']['x1_isa']['remaining_counts']})
    records.sort(key=lambda r:(r[0],r[1]));blob=encode_table(records);require(len(parse_table(blob))==len(records)<=MAX_ENTRIES,'table capacity mismatch')
    args.output.mkdir(parents=True);target=args.output/'text-fixups-ios27.bin';target.write_bytes(blob)
    (args.output/'text-fixups-ios27.txt').write_bytes(blob.replace(b'\0',b'\n'))
    manifest={'schema':'zeta-ios27-original-child-text-fixups-v1','qualification':'DEFAULT-OFF SOURCE PROFILE ONLY','adt_property':'/chosen/text-fixups-ios27','kernel_flag':'XNU_IOS27_TEXT_FIXUPS=1','kernel_profile_selected':False,
              'table':record(target),'descriptor_count':len(records),'instruction_edits':total,'max_entries':MAX_ENTRIES,'files':files,
              'required_bingrade':'bingrade=0x100000c:0x0000000c:0x80000000','bingrade_evidence':record(args.child_checkpoint/'bingrade-host/result.json'),
              'runtime_identity_guard':'Validated original signed page, vnode basename, exact original bytes; no whole-file SHA/CDHash lookup in the fault path',
              'table_installation':'Whole new table rejected on malformed/order/overflow/overlap; legacy32-entry mechanism preserved separately',
              'original_files_modified':False,'executable_outputs_written':False,'kernel_built':False,'phone_commands':False,
              'tools':{p.name:record(p) for p in [Path(__file__),HERE/'zeta_text_fixups.py',HERE/'zeta_x1_compat.py',HERE/'zeta_userland_pauth.py']}}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'instructions':total,'descriptors':len(records),'adt_bytes':len(blob),'selected':False},indent=2))


if __name__=='__main__':main()
