"""Explicit x1 experiment contract and exact pointer lowering; never infer policy.

A draft is useful for planning, but cannot enable executable conversion. The
runtime evidence must identify the exact tested kernel, not just source intent.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct

PROFILE = 'sm8350-x1-experimental-v1'
CSSC = {'umin','umax','smin','smax','ctz','cnt','abs'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def lower_pointer_off(word, effective_cpta):
    """Exact one-word ADDPT/SUBPT lowering only under explicit effective CPTA OFF.

    Mirrors the qualified pure C planner, but does not read host capabilities.
    Rn/Rd31 need SP semantics: extended UXTX only permits shifts0..4.
    """
    if effective_cpta=='off' and word&0xffe08000==0x9b600000:
        return 'maddpt',0x9b000000|(word&0x001f7fff)
    if effective_cpta != 'off' or word & 0xffe0e000 not in (0x9a002000,0xda002000):
        return None
    rd,rn,shift=word&31,(word>>5)&31,(word>>10)&7
    base=0x8b000000|(word&0x40000000)
    if rd==31 or rn==31:
        if shift>4:
            raise ValueError('pointer SP form needs a multiword sequence for shift>4')
        base|=0x00206000
    return ('subpt' if word&0x40000000 else 'addpt'),base|(word&0x001f1fff)


def cssc(word):
    if word&0x7ffffc00==0x5ac01800:return 'ctz'
    if word&0x7ffffc00==0x5ac02000:return 'abs'
    if word&0x7ffffc00==0x5ac01c00:return 'cnt'
    reg=word&0x7fe0fc00;imm=word&0x7ffc0000
    return {0x1ac06000:'smax',0x1ac06400:'umax',0x1ac06800:'smin',0x1ac06c00:'umin'}.get(reg) or {
        0x11c00000:'smax',0x11c40000:'umax',0x11c80000:'smin',0x11cc0000:'umin'}.get(imm)


def retained_feature(word, mnemonic):
    # Exact known permission system register: TINDEX_EL0. Apple S3_6_C15_C1_5
    # uses the same masking of the Rt field. Neither is rewritten to a NOP.
    if word&0xfffdf000 in (0xd5900000,0xd5940000) or word&0xfffdfc00 in (0xd5800000,0xd5840000) or word&0xffffffe0 in (
            0xd53b4060,0xd51b4060,0xd53ef1a0,0xd51ef1a0):return 'tpro'
    if mnemonic in ('ldg','stg','stzg','st2g','stz2g','irg','gmi','addg','subg','subp','subps'):
        return 'mte'
    if mnemonic.startswith('sha512'):return 'sha512'
    if mnemonic=='amx':return 'amx'
    if mnemonic in ('ldapur','ldapurb','ldapurh','ldapursb','ldapursh','ldapursw','stlur','stlurb','stlurh'):return 'rcpc2'
    return None


def rejected_by_baseline(words):
    ordered=sorted(set(words))
    if not ordered:return set()
    source=''.join(' '.join(f'0x{b:02x}' for b in w.to_bytes(4,'little'))+'\n' for w in ordered)
    result=subprocess.run(['llvm-mc','--disassemble','-triple=aarch64','-mcpu=cortex-a55'],
                          input=source,text=True,capture_output=True,check=True)
    invalid=set()
    for line in result.stderr.splitlines():
        if line.startswith('<stdin>:'):
            match=re.fullmatch(r'<stdin>:(\d+):\d+: warning: invalid instruction encoding',line)
            require(match is not None,'unexpected baseline LLVM diagnostic: '+line)
            invalid.add(int(match[1]))
        elif line.strip() and not line.startswith(('0x','^')):
            raise ValueError('unexpected baseline LLVM diagnostic: '+line)
    require(all(1<=n<=len(ordered) for n in invalid),'baseline diagnostic outside input')
    return {ordered[n-1] for n in invalid}


def artifact(record, directory):
    require(isinstance(record,dict),'missing contract artifact record')
    require(isinstance(record.get('path'),str) and bool(record['path']),'missing contract artifact path')
    path=Path(record['path'])
    if not path.is_absolute():path=directory/path
    digest=record.get('sha256','')
    require(re.fullmatch('[0-9a-f]{64}',digest or '') is not None,'missing exact artifact SHA-256')
    data=path.read_bytes()
    require(hashlib.sha256(data).hexdigest()==digest,'contract artifact hash mismatch: '+str(path))
    return data


def probe_cdhash(data):
    """SHA-256 CodeDirectory identity used by self CS_OPS_CDHASH (not trust proof)."""
    require(len(data)>=32 and struct.unpack_from('<I',data)[0]==0xfeedfacf,'probe is not thin 64-bit Mach-O')
    count,commands=struct.unpack_from('<II',data,16);require(32+commands<=len(data),'probe load commands leave image')
    at=32;signature=None
    for _ in range(count):
        require(at+8<=32+commands,'truncated probe command')
        command,size=struct.unpack_from('<II',data,at)
        require(size>=8 and at+size<=32+commands,'invalid probe command size')
        if command==0x1d:
            require(size>=16 and signature is None,'invalid duplicate probe signature')
            signature=struct.unpack_from('<II',data,at+8)
        at+=size
    require(signature is not None,'probe lacks embedded signature')
    offset,length=signature;require(offset+length<=len(data) and length>=12,'probe signature leaves image')
    magic,total,count=struct.unpack_from('>III',data,offset)
    require(magic==0xfade0cc0 and 12+8*count<=total<=length,'invalid probe signature superblob')
    directories=[]
    for index in range(count):
        slot,relative=struct.unpack_from('>II',data,offset+12+index*8)
        if slot!=0:continue
        require(relative+44<=total,'probe CodeDirectory leaves signature')
        begin=offset+relative;magic,size=struct.unpack_from('>II',data,begin)
        require(magic==0xfade0c02 and 44<=size<=total-relative and data[begin+37]==2,'probe primary CodeDirectory is not SHA-256')
        directories.append(hashlib.sha256(data[begin:begin+size]).digest()[:20].hex())
    require(len(directories)==1,'probe primary CodeDirectory is missing/ambiguous')
    return directories[0]


def load_contract(path):
    """Validate exact local artifacts/evidence. A draft or untested kernel fails closed."""
    path=Path(path).resolve();raw=path.read_bytes();value=json.loads(raw)
    require(value.get('schema')=='zeta-x1-kernel-contract-v1','unsupported x1 contract schema')
    require(value.get('profile')==PROFILE,'wrong x1 conversion profile')
    require(value.get('qualification')=='validated','x1 contract is draft; runtime qualification is pending')
    kernel=value.get('kernel',{});kernel_hash=kernel.get('image',{}).get('sha256')
    for key in ['image','source_manifest','compat_helper','compat_adapter']:
        artifact(kernel.get(key),path.parent)
    policy=value.get('policy',{})
    for key,expected in {'ordinary_pointer_abi':True,'pauth_advertised':False,
                         'effective_cpta':'off','cpa2_advertised':False,
                         'mte_advertised':False,'gcs_enabled':False,'gcs_advertised':False,'signature_page_shift':12}.items():
        require(type(policy.get(key)) is type(expected) and policy[key]==expected,'unqualified x1 policy: '+key)
    css=policy.get('cssc',{})
    require(css.get('linked') is True and css.get('opt_in_el0') is True and
            css.get('runtime_validated') is True and css.get('scope')=='platform-task' and set(css.get('forms',[]))==CSSC,
            'CSSC EL0 helper has not been qualified for all supported forms')
    tpro=policy.get('tpro',{})
    require(tpro.get('apple_keys_omitted')==['dyld_hw_tpro','dyld_hw_tpro_pagers'] and
            type(tpro.get('commpage_version')) is int and tpro['commpage_version']==0 and tpro.get('protected_stack') is False,
            'hardware TPRO disabled-path contract is incomplete')
    guest=json.loads(artifact(value.get('guest_isa_evidence'),path.parent))
    require(guest.get('schema')=='zeta-x1-guest-isa-evidence-v1' and
            guest.get('kernel_sha256')==kernel_hash,'guest ISA evidence does not match kernel')
    require(all(guest.get('observed',{}).get(k)==v for k,v in {'pauth':'absent','cpa':'absent','cpa2_advertised':False}.items()),
            'guest ISA evidence is absent or incompatible')
    runtime=json.loads(artifact(value.get('el0_runtime_evidence'),path.parent))
    require(runtime.get('schema')=='zeta-x1-el0-compat-evidence-v1' and
            runtime.get('kernel_sha256')==kernel_hash,'EL0 evidence does not match kernel')
    required={'checked_instruction_fetch','pc_advance_once','fault_no_mutation',
              'unsupported_fallthrough','cssc_32_64_zr_nzcv','cssc_opt_in_only','cssc_platform_scope','gcs_disabled_unadvertised'}
    require(all(runtime.get('tests',{}).get(k)=='pass' for k in required),
            'EL0 code-fetch/PC/fault/semantic validation is incomplete')
    process=runtime.get('platform_process',{})
    probe=process.get('probe',{});probe_data=artifact(probe,path.parent)
    basename=process.get('basename')
    require(isinstance(basename,str) and basename==Path(basename).name and basename not in ('','zeta-isa-probe'),
            'platform-scope probe must have distinct basename')
    identity=probe_cdhash(probe_data)
    require(process.get('cdhash')==identity,'platform-scope probe CDHash mismatches executable')
    for key,mode,result in [('mode1_negative',1,'sigill'),('mode2_positive',2,'pass')]:
        observation=process.get(key,{})
        status=observation.get('csops_status')
        require(observation.get('kernel_sha256')==kernel_hash and type(observation.get('kernel_mode')) is int and observation['kernel_mode']==mode and
                observation.get('basename')==basename and observation.get('csops_cdhash')==identity and
                type(observation.get('csops_status_result')) is int and observation['csops_status_result']==0 and
                type(observation.get('csops_cdhash_result')) is int and observation['csops_cdhash_result']==0 and
                type(status) is int and status&0x04000000 and observation.get('cssc')==result,
                'platform process identity/scope negative-positive evidence is incomplete: '+key)
        artifact(observation.get('capture'),path.parent)
    for evidence in (guest,runtime):
        artifact(evidence.get('capture'),path.parent)
    return dict(value,path=str(path),sha256=hashlib.sha256(raw).hexdigest())


def retained_authorized(contract, family, input_sha256=None):
    """Known guarded/native features need explicit evidence; their words are retained."""
    record=contract.get('retained_features',{}).get(family,{})
    if record.get('mode') not in ('observed-native','verified-disabled-path'):
        return False
    try:
        evidence=json.loads(artifact(record.get('evidence'),Path(contract['path']).parent))
    except (OSError,ValueError,KeyError,TypeError):return False
    if record.get('mode')=='verified-disabled-path' and evidence.get('input_sha256')!=input_sha256:
        return False
    return (evidence.get('schema')=='zeta-x1-retained-feature-evidence-v1' and
            evidence.get('family')==family and evidence.get('kernel_sha256')==contract['kernel']['image']['sha256']
            and evidence.get('result')=='pass')
