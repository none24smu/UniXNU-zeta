"""Explicit policy and independent C/Python planner agreement; no phone artifacts."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPTS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SCRIPTS))
import zeta_x1_compat as x1
import zeta_userland_code as code
import zeta_userland_pauth as pauth
import zeta_dyld_cache as cache
spec=importlib.util.spec_from_file_location('x1_rewrite',SCRIPTS/'rewrite-zeta-userland.py')
rewrite=importlib.util.module_from_spec(spec);spec.loader.exec_module(rewrite)


def fixture(directory):
    def save(name,data):
        raw=data if isinstance(data,bytes) else json.dumps(data).encode()
        path=directory/name;path.write_bytes(raw)
        return {'path':name,'sha256':hashlib.sha256(raw).hexdigest()}
    kernel=save('kernel',b'SYNTHETIC TEST KERNEL; NOT A DEVICE ARTIFACT')
    capture=save('capture',b'SYNTHETIC TEST CAPTURE')
    guest=save('guest.json',{'schema':'zeta-x1-guest-isa-evidence-v1','kernel_sha256':kernel['sha256'],
                             'observed':{'pauth':'absent','cpa':'absent','cpa2_advertised':False},'capture':capture})
    code_directory=bytearray(44);struct.pack_into('>II',code_directory,0,0xfade0c02,len(code_directory));code_directory[37]=2
    signature=struct.pack('>IIIII',0xfade0cc0,20+len(code_directory),1,0,20)+code_directory
    probe=save('platform-probe',struct.pack('<8I',0xfeedfacf,0x100000c,0,2,1,16,0,0)+struct.pack('<4I',0x1d,16,48,len(signature))+signature)
    identity=hashlib.sha256(code_directory).digest()[:20].hex()
    process={'probe':probe,'basename':'zeta-platform-isa-probe','cdhash':identity}
    for key,mode,result in [('mode1_negative',1,'sigill'),('mode2_positive',2,'pass')]:
        process[key]={'kernel_sha256':kernel['sha256'],'kernel_mode':mode,'basename':process['basename'],
                      'csops_cdhash':identity,'csops_status':0x04000000,'csops_status_result':0,'csops_cdhash_result':0,'cssc':result,'capture':capture}
    runtime=save('runtime.json',{'schema':'zeta-x1-el0-compat-evidence-v1','kernel_sha256':kernel['sha256'],
        'tests':{k:'pass' for k in ['checked_instruction_fetch','pc_advance_once','fault_no_mutation',
          'unsupported_fallthrough','cssc_32_64_zr_nzcv','cssc_opt_in_only','cssc_platform_scope','gcs_disabled_unadvertised']},'capture':capture,'platform_process':process})
    value={'schema':'zeta-x1-kernel-contract-v1','profile':x1.PROFILE,'qualification':'validated',
      'kernel':{'image':kernel,'source_manifest':save('source.json',{}),
                'compat_helper':save('helper',b'test helper'),'compat_adapter':save('adapter',b'test adapter')},
      'policy':{'ordinary_pointer_abi':True,'pauth_advertised':False,'effective_cpta':'off',
                'cpa2_advertised':False,'mte_advertised':False,'gcs_enabled':False,'gcs_advertised':False,'signature_page_shift':12,
                'cssc':{'linked':True,'opt_in_el0':True,'runtime_validated':True,'scope':'platform-task','forms':sorted(x1.CSSC)},
                'tpro':{'apple_keys_omitted':['dyld_hw_tpro','dyld_hw_tpro_pagers'],
                        'commpage_version':0,'protected_stack':False}},
      'guest_isa_evidence':guest,'el0_runtime_evidence':runtime,'retained_features':{}}
    path=directory/'contract.json';path.write_text(json.dumps(value));return path,value


class ContractTests(unittest.TestCase):
    def test_synthetic_validated_contract_and_draft_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            path,value=fixture(Path(d));self.assertEqual(x1.load_contract(path)['policy']['effective_cpta'],'off')
            value['qualification']='draft';path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'draft'):x1.load_contract(path)
    def test_kernel_capture_and_policy_tampering_refused(self):
        for change in ['kernel','capture','policy','policy-type','runtime']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as d:
                directory=Path(d);path,value=fixture(directory)
                if change in ['kernel','capture']:(directory/change).write_bytes(b'changed')
                if change=='policy':value['policy']['effective_cpta']='unknown'
                if change=='policy-type':value['policy']['pauth_advertised']=0
                if change=='runtime':
                    runtime=json.loads((directory/'runtime.json').read_text());runtime['kernel_sha256']='a'*64
                    raw=json.dumps(runtime).encode();(directory/'runtime.json').write_bytes(raw)
                    value['el0_runtime_evidence']['sha256']=hashlib.sha256(raw).hexdigest()
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):x1.load_contract(path)
    def test_platform_identity_or_probe_exception_cannot_qualify_scope(self):
        for change in ['platform','identity','basename','negative-control']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as d:
                directory=Path(d);path,value=fixture(directory)
                runtime=json.loads((directory/'runtime.json').read_text());process=runtime['platform_process']
                if change=='platform':process['mode2_positive']['csops_status']=0
                if change=='identity':process['mode2_positive']['csops_cdhash']='0'*40
                if change=='basename':process['basename']='zeta-isa-probe'
                if change=='negative-control':process['mode1_negative']['cssc']='pass'
                raw=json.dumps(runtime).encode();(directory/'runtime.json').write_bytes(raw)
                value['el0_runtime_evidence']['sha256']=hashlib.sha256(raw).hexdigest();path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):x1.load_contract(path)

    def test_gcs_and_failed_csops_cannot_qualify_contract(self):
        for change in ['gcs-on','gcs-advertised','gcs-unknown','gcs-test-missing','status-error','cdhash-error','status-bool']:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as d:
                directory=Path(d);path,value=fixture(directory)
                runtime=json.loads((directory/'runtime.json').read_text())
                if change=='gcs-on':value['policy']['gcs_enabled']=True
                if change=='gcs-advertised':value['policy']['gcs_advertised']=True
                if change=='gcs-unknown':value['policy'].pop('gcs_enabled')
                if change=='gcs-test-missing':runtime['tests'].pop('gcs_disabled_unadvertised')
                if change=='status-error':runtime['platform_process']['mode2_positive']['csops_status_result']=-1
                if change=='cdhash-error':runtime['platform_process']['mode2_positive']['csops_cdhash_result']=-1
                if change=='status-bool':runtime['platform_process']['mode2_positive']['csops_status_result']=False
                raw=json.dumps(runtime).encode();(directory/'runtime.json').write_bytes(raw)
                value['el0_runtime_evidence']['sha256']=hashlib.sha256(raw).hexdigest();path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):x1.load_contract(path)

    def test_retained_disabled_path_bound_to_original_image(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);path,value=fixture(directory)
            evidence={'schema':'zeta-x1-retained-feature-evidence-v1','family':'tpro',
                      'kernel_sha256':value['kernel']['image']['sha256'],'input_sha256':'b'*64,'result':'pass'}
            raw=json.dumps(evidence).encode();(directory/'retained.json').write_bytes(raw)
            value['retained_features']['tpro']={'mode':'verified-disabled-path','evidence':{'path':'retained.json','sha256':hashlib.sha256(raw).hexdigest()}}
            path.write_text(json.dumps(value));contract=x1.load_contract(path)
            self.assertTrue(x1.retained_authorized(contract,'tpro','b'*64))
            self.assertFalse(x1.retained_authorized(contract,'tpro','c'*64))
            self.assertFalse(x1.retained_authorized(contract,'mte','b'*64))
    def test_unknown_isa_and_missing_feature_evidence_stop_conversion(self):
        with tempfile.TemporaryDirectory() as d:
            path,_=fixture(Path(d));contract=x1.load_contract(path)
            proof={'anomalies':{},'x1_isa':{'input_sha256':'b'*64,'remaining_counts':{'unknown-isa':1}}}
            with self.assertRaisesRegex(ValueError,'unresolved ISA'):rewrite.qualify_x1_proof(proof,contract)
            proof['x1_isa']['remaining_counts']={'retained-tpro':1}
            with self.assertRaisesRegex(ValueError,'lacks evidence'):rewrite.qualify_x1_proof(proof,contract)
            proof['x1_isa']['remaining_counts']={'cssc-trap':9}
            rewrite.qualify_x1_proof(proof,contract)


class PlannerTests(unittest.TestCase):
    def test_exact_python_lowering_matches_independently_checked_c_helper(self):
        with tempfile.TemporaryDirectory() as d:
            library=Path(d)/'helper.so'
            subprocess.run([shutil.which('clang'),'-shared','-fPIC','-O2',str(SCRIPTS.parent/'package/ZetaUserInstructionCompat.c'),'-o',str(library)],check=True,capture_output=True)
            fn=ctypes.CDLL(str(library)).ZetaUserInstructionCompatLowerPointerOff
            fn.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.POINTER(ctypes.c_uint32)]
            rng=random.Random(0x192704)
            for _ in range(25000):
                base=rng.choice([0x9a002000,0xda002000,0x9b600000])
                bits=rng.getrandbits(32)&(0x001f7fff if base==0x9b600000 else 0x001f1fff)
                word=base|bits;output=ctypes.c_uint32(0xdeadbeef);accepted=fn(word,1,ctypes.byref(output))
                try:planned=x1.lower_pointer_off(word,'off')
                except ValueError:planned=None
                self.assertEqual(bool(accepted),planned is not None)
                if planned:self.assertEqual(output.value,planned[1])
                for policy in ['on','unknown',None]:self.assertIsNone(x1.lower_pointer_off(word,policy))
    def test_permission_encodings_decode_but_cannot_be_lowered(self):
        for base in [0xd5900000,0xd5940000,0xd5800000,0xd5840000]:
            for rd in [0,30,31]:
                for operand in [0,1,31] if base in [0xd5800000,0xd5840000] else [0,1,2,127]:
                    for nb in [0,1]:
                        word=base|rd|(operand<<5)|(nb<<17)
                        self.assertIsNotNone(code.decode_permission_transition(word))
                        self.assertEqual(x1.retained_feature(word,''),'tpro')
                        self.assertIsNone(pauth.lower(word));self.assertIsNone(x1.lower_pointer_off(word,'off'))
        self.assertIsNone(code.decode_permission_transition(0xd5901000))
    def test_x1_default_remains_rejected(self):
        header=struct.pack('<8I',0xfeedfacf,0x100000c,0x8000000c,2,0,0,0,0)
        with self.assertRaisesRegex(ValueError,'analysis-only'):rewrite.rewrite(header)
    def test_expected_cssc_forms_and_rcpc_are_distinct(self):
        self.assertEqual(x1.cssc(0xdac01c20),'cnt')
        self.assertEqual(x1.retained_feature(0xd9410008,'ldapur'),'rcpc2')
        self.assertIsNone(x1.cssc(0xd9410008))


class DetachedStubTests(unittest.TestCase):
    class Memory:
        def __init__(self,word_changes=None,executable=True):
            self.executable=executable
            words=[0x90000001,0x91000021,0x140003fe,0xd4200020]
            for index,value in (word_changes or {}).items():words[index]=value
            self.data=struct.pack('<4I',*words)
        def locate(self,address):
            if not 0x1000<=address<0x3000:raise KeyError(address)
            return 0,address-0x1000,0x3000-address
        def executable_regions(self,initial_only=False):return [(0x1000,0x2000,0,0)] if self.executable else []
        def read(self,address,length):return self.data[address-0x1000:address-0x1000+length]
    def test_only_exact_executable_thunk_to_owned_code_is_accepted(self):
        coverage=cache.Coverage([(0x2000,0x2004)],self.Memory(),True)
        self.assertIn(0x1000,coverage)
        self.assertEqual(coverage.detached_stubs[0x1000]['target'],0x2000)
        self.assertNotIn(0x1004,coverage)
        for index,value in [(0,0x90000000),(1,0x91000000),(2,0x940003fe),(3,0xd503201f)]:
            bad=cache.Coverage([(0x2000,0x2004)],self.Memory({index:value}),True)
            self.assertNotIn(0x1000,bad)
        no_owner=cache.Coverage([],self.Memory(),True)
        self.assertNotIn(0x1000,no_owner)
        nonexec=cache.Coverage([(0x2000,0x2004)],self.Memory(executable=False),True)
        self.assertNotIn(0x1000,nonexec)
        disabled=cache.Coverage([(0x2000,0x2004)],self.Memory(),False)
        self.assertNotIn(0x1000,disabled)


class NoReturnTests(unittest.TestCase):
    def test_only_symbol_qualified_direct_call_can_terminate_path(self):
        insns={0x1000:('bl','#0x2000')}
        unqualified=cache.Coverage([(0x2000,0x2004)])
        self.assertIsNone(code.walk(insns,b'',lambda a,n:0,[0x1000],set(),set(),True,set(),unqualified))
        qualified=cache.Coverage([(0x2000,0x2004)],noreturn_exports=[0x2000])
        result=code.walk(insns,b'',lambda a,n:0,[0x1000],set(),set(),True,set(),qualified)
        self.assertEqual(result[0],{0x1000});self.assertEqual(qualified.reached,{0x2000})
    def test_noreturn_thunk_must_match_exact_executable_forwarder(self):
        class Memory:
            def executable_regions(self,initial_only=False):return [(0x1000,16,0,0)]
            def read(self,a,n):return struct.pack('<4I',0xb0000010,0x91000210,0xd61f0200,0xd4200020)
        coverage=cache.Coverage([],Memory(),noreturn_exports=[0x2000])
        self.assertTrue(coverage.is_noreturn(0x1000))
        self.assertFalse(coverage.is_noreturn(0x1004))
        self.assertFalse(cache.Coverage([],Memory(),noreturn_exports=[0x3000]).is_noreturn(0x1000))

if __name__=='__main__':unittest.main()
