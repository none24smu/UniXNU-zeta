#!/usr/bin/env python3
"""Audit retained JS boot-policy and per-core ISA evidence offline.

The aborted live-policy attempt contributes its completed disabled phase only.
Successful boot-policy phases are separate boots, never an off-again/live-toggle
claim. This tool does not access a phone or qualify a converted OS.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from normalize_zeta_native_common import record, require, unique, mach_window
from zeta_x1_compat import probe_cdhash


def check_phase(phase,raw,mode,selector,enabled):
    text=raw.read_text();rows=[json.loads(s) for s in text.splitlines() if s.startswith('{')]
    require(rows==phase['records'],'raw phase/summary discrepancy')
    require(phase.get('passed') is True and phase.get('gate_consumed') is True,'incomplete phase')
    require(phase['mode']==mode and phase['selector']==selector,'phase policy identity')
    require(f'zeta-isa-launcher: selection {selector}' in text and 'zeta-isa-launcher: child status 0' in text,'launcher did not complete')
    require(unique(rows,'complete')=={'kind':'complete','cssc_cases':32,'passed':0,'trapped':32,'failures':0},'CSSC was not disabled')
    expected_names={'exact-sticky-fpsr','negative-zero','positive-fraction','negative-fraction','modulo32','qnan','subnormal','refuse-fz'}
    states=[r for r in rows if r['kind']=='js-state']
    require(len(states)==32 and {(s['name'],s['destination']) for s in states}=={(n,d) for n in expected_names for d in (0,29,30,31)},'saved-state fixture coverage')
    for s in states:
        want=enabled and s['name']!='refuse-fz'
        require(s['fpcr']==(0x1000000 if s['name']=='refuse-fz' else 0),'unqualified FPCR domain')
        require(s['mismatches']==0 and s['signal']==(0 if want else 4) and s['passed'] is want and s['q_registers_compared']==(32 if want else 0),'saved Q/GPR/FP-state mismatch')
    caps=[r for r in rows if r['kind']=='capability' and r['name'].startswith('fjcvtzs-')]
    want_values={'zero':0,'positive-fraction':3,'negative-fraction':0xfffffffe,'modulo32':1,'qnan':0,'infinity':0}
    require(len(caps)==6 and {r['name'][8:] for r in caps}==set(want_values),'JS value fixture coverage')
    for r in caps:
        require(r['signal']==(0 if enabled else 4) and r['semantic_pass'] is enabled,'JS value/signals mismatch')
        if enabled:require(int(r['result'],16)==want_values[r['name'][8:]],'JS result mismatch')
    delta=[b-a for a,b in zip(phase['before'],phase['after'])]
    expected=[38,34,0,0,0,0,4,0] if enabled else [38,0,38,0,0,0,0,0] if mode==0 else [38,0,0,38,0,0,0,0]
    require(len(delta)==8 and delta==phase['counter_delta']==expected,'JS counters mismatch')
    flags=unique(rows,'code-signing');identity=unique(rows,'code-directory')
    require(flags['status']==0 and flags['platform_binary'] is True and int(flags['flags'],16)&0x04000000 and identity['status']==0,'platform identity failed')
    apple=[r for r in rows if r['kind']=='apple-parameter']
    require(len(apple)==4 and {r['name'] for r in apple}=={'has_sec_transition','dyld_hw_tpro','dyld_hw_tpro_pagers','security_config'},'Apple vector coverage')
    require(all(r['vector_present'] is True and r['present'] is (r['name']=='security_config') for r in apple),'Apple vector guard/control mismatch')
    return {'name':phase['name'],'mode':mode,'selector':selector,'basename':'zeta-isa-test' if selector=='p' else 'zeta-isa-probe',
            'raw':record(raw),'emulated':delta[1],'saved_state_successes':28 if enabled else 0,
            'value_successes':6 if enabled else 0,'refused_fz_cases':4 if enabled else 0,'denied_cases':0 if enabled else 38,
            'csops_status':int(flags['flags'],16),'cdhash':identity['cdhash'],'apple_parameters':apple}


def normalize(directory):
    h=Path(directory).resolve();kernel=h/'js-candidate-kernel.macho';kernel_record=record(kernel);data=kernel.read_bytes()
    artifact=h/'isa-artifact-v4';build=json.loads((artifact/'build.json').read_text())
    probe=record(artifact/'zeta-isa-probe');cdhash=probe_cdhash((artifact/'zeta-isa-probe').read_bytes())
    require(cdhash==build['files']['zeta-isa-probe']['cdhash'],'probe CDHash mismatch')
    for name,v in build['files'].items():
        a=record(artifact/name);require(a['sha256']==v['sha256'] and a['bytes']==v['bytes'],'probe artifact mismatch')
    definitions=[('native-js-result1.json','js-native','js-readback-',[('off',0,'i',False,'native-js1-0-off.log')]),
                 ('native-js-bootmode1-result1.json','js-boot1-native','js-boot1-readback-',[('probe-enabled',1,'i',True,'native-js-boot1-0-probe-enabled.log'),('platform-name-denied',1,'p',False,'native-js-boot1-1-platform-name-denied.log')]),
                 ('native-js-bootmode2-result1.json','js-boot2-native','js-boot2-readback-',[('platform-enabled',2,'p',True,'native-js-boot2-0-platform-enabled.log')])]
    observations=[];results=[];windows=[]
    for index,(name,suffix,readback,phases) in enumerate(definitions):
        result=json.loads((h/name).read_text());require(result['kernel_sha256']==kernel_record['sha256'],'phase kernel identity mismatch')
        require(len(result['phases'])==len(phases),'unexpected/uncompleted phase count')
        if index==0:
            require(result.get('passed') is not True,'aborted live experiment incorrectly reports overall pass')
        else:
            require(result.get('passed') is True and result.get('policy_control')=='boot argument; no live mode writes','boot policy result incomplete')
            require(f'zeta-js-compat={index}' in result['boot_args'].split(),'boot mode argument mismatch')
        for symbol,window in result['kernel_runtime'].items():
            path=h/(symbol+'-'+suffix+'.bin');actual=path.read_bytes()
            require(len(actual)==window['bytes']==128 and hashlib.sha256(actual).hexdigest()==window['sha256'],'runtime window file mismatch')
            require(actual==mach_window(data,int(window['va'],16),len(actual)),'runtime bytes differ from selected kernel')
            windows.append(record(path))
        for executable,expected in build['files'].items():
            got=record(h/(readback+executable));require(got['sha256']==expected['sha256'] and got['bytes']==expected['bytes'],'physical executable readback mismatch')
            require(result['executables'][executable]=={'sha256':got['sha256'],'bytes':got['bytes']},'executable report mismatch')
        for phase,(label,mode,selector,enabled,log) in zip(result['phases'],phases):
            require(phase['name']==label,'phase label mismatch')
            observation=check_phase(phase,h/log,mode,selector,enabled)
            require(observation['cdhash']==cdhash,'native CDHash differs from signed artifact')
            observation.update(boot_id=index,kernel_sha256=kernel_record['sha256'],control='disabled phase before failed live activation' if index==0 else 'separate immutable boot policy')
            observations.append(observation)
        results.append(record(h/name))
    isa_path=h/'native-isa-registers1/result.json';isa=json.loads(isa_path.read_text())
    require(isa['kernel_sha256']==kernel_record['sha256'] and isa['active_cpus']==8 and len(isa['cpus'])==8,'ISA kernel/core coverage mismatch')
    cpus=[]
    for index,cpu in enumerate(isa['cpus']):
        path=isa_path.parent/f'cpu{index}.log'
        regs={n:int(v,16) for n,v in re.findall(r'([a-z][a-z0-9]*) (0x[0-9a-f]{16})',path.read_text())}
        require(set(regs)=={'midr','mpidr','pfr0','pfr1','isar0','isar1','isar2','mmfr0','mmfr1','mmfr2'},'raw ISA register coverage')
        require(cpu['requested_cpu']==index and regs=={n:int(v,16) for n,v in cpu['registers'].items()},'raw ISA/report discrepancy')
        require((regs['pfr1']>>44)&15==cpu['gcs_field']==0,'guest GCS feature is not absent')
        cpus.append({'cpu':index,'mpidr':hex(regs['mpidr']),'midr':hex(regs['midr']),'pfr1':hex(regs['pfr1']),'gcs_field':0,'raw':record(path)})
    require(len({c['mpidr'] for c in cpus})==8,'CPU binding duplicated a guest CPU')
    for symbol,window in isa['runtime_code'].items():
        actual=(isa_path.parent/(symbol+'.bin')).read_bytes()
        require(len(actual)==128 and hashlib.sha256(actual).hexdigest()==window['sha256'] and actual==mach_window(data,int(window['va'],16),128),'ISA reader runtime kernel mismatch')
    return {'schema':'zeta-x1-native-js-gcs-checkpoint-v1','normalizer':record(__file__),'kernel':kernel_record,'artifact_build':record(artifact/'build.json'),'probe':probe,'probe_cdhash':cdhash,
            'raw_results':results,'runtime_windows':windows,'observations':observations,'isa_raw_result':record(isa_path),'cpus':cpus,
            'js_default_fpcr_boot_policy_scope_passed':True,'js_native_fpcr_values':[0],'js_fz1_refused':True,
            'gcs_feature_absent_all_eight_online_guest_cpus':True,'gcs_controls_accessed':False,
            'live_policy_toggle_qualified':False,'off_again_phase_observed':False,'conversion_qualified':False,
            'limits':['Three independent boot policies; the attempted live activation sequence did not finish',
                      'Native saved-state validation covers only FPCR=0 successes and FZ=1 refusals; wider helper domain remains host/oracle evidence',
                      'CSSC qualification belongs to the separate ec2 kernel, not this kernel with CSSC disabled',
                      'Apple-vector observations belong to the iOS26 diagnostic processes, not an initial iOS27 process',
                      'GCS absence is the guest architectural ID field on eight distinct online CPUs; no nonexistent GCS controls were read',
                      'No converted iOS27 cache or whole-OS qualification']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',required=True);p.add_argument('--output',required=True);args=p.parse_args()
    output=Path(args.output);require(not output.exists(),'preserve original normalization output')
    output.write_text(json.dumps(normalize(args.directory),indent=2)+'\n');print(output)


if __name__=='__main__':main()
