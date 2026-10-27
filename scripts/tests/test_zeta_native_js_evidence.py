"""Offline normalization must not turn a partial live attempt into a pass."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

SCRIPTS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SCRIPTS))
spec=importlib.util.spec_from_file_location('native_js_normalize',SCRIPTS/'normalize-zeta-native-js.py')
js=importlib.util.module_from_spec(spec);spec.loader.exec_module(js)
from normalize_zeta_native_common import mach_window


def fixture(enabled=True):
    rows=[{'kind':'complete','cssc_cases':32,'passed':0,'trapped':32,'failures':0},
          {'kind':'code-signing','status':0,'platform_binary':True,'flags':'0x04000000'},
          {'kind':'code-directory','status':0,'cdhash':'a'*40}]
    for name in ['exact-sticky-fpsr','negative-zero','positive-fraction','negative-fraction','modulo32','qnan','subnormal','refuse-fz']:
        for destination in (0,29,30,31):
            want=enabled and name!='refuse-fz'
            rows.append({'kind':'js-state','name':name,'destination':destination,'fpcr':0x1000000 if name=='refuse-fz' else 0,'signal':0 if want else 4,'mismatches':0,'passed':want,'q_registers_compared':32 if want else 0})
    for name,value in [('zero',0),('positive-fraction',3),('negative-fraction',0xfffffffe),('modulo32',1),('qnan',0),('infinity',0)]:
        rows.append({'kind':'capability','name':'fjcvtzs-'+name,'signal':0 if enabled else 4,'semantic_pass':enabled,'result':hex(value if enabled else 0)})
    for name in ['has_sec_transition','dyld_hw_tpro','dyld_hw_tpro_pagers','security_config']:
        rows.append({'kind':'apple-parameter','name':name,'vector_present':True,'present':name=='security_config'})
    delta=[38,34,0,0,0,0,4,0] if enabled else [38,0,0,38,0,0,0,0]
    return {'name':'test','mode':1,'selector':'p','passed':True,'gate_consumed':True,'before':[0]*8,'after':delta,'counter_delta':delta,'records':rows}


class JsEvidenceTests(unittest.TestCase):
    def validate(self,phase,enabled=True):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'raw.log'
            path.write_text('zeta-isa-launcher: selection p\n'+'\n'.join(json.dumps(r) for r in phase['records'])+'\nzeta-isa-launcher: child status 0\n')
            return js.check_phase(phase,path,1,'p',enabled)

    def test_default_fpcr_success_and_denied_phase_counts(self):
        self.assertEqual(self.validate(fixture())['emulated'],34)
        self.assertEqual(self.validate(fixture(False),False)['denied_cases'],38)

    def test_counter_coverage_fp_state_fz_and_apple_control_tampering_refused(self):
        for change in ['counter','q-bank','fpcr','duplicate','fz-enabled','value','apple-control','platform','incomplete']:
            phase=fixture();rows=phase['records']
            if change=='counter':phase['after']=phase['after'].copy();phase['after'][1]+=1
            if change=='q-bank':next(r for r in rows if r['kind']=='js-state')['q_registers_compared']=31
            if change=='fpcr':next(r for r in rows if r['kind']=='js-state')['fpcr']=0x400000
            if change=='duplicate':rows.append(copy.deepcopy(next(r for r in rows if r['kind']=='js-state')))
            if change=='fz-enabled':next(r for r in rows if r.get('name')=='refuse-fz')['passed']=True
            if change=='value':next(r for r in rows if r.get('name')=='fjcvtzs-zero')['result']='0x1'
            if change=='apple-control':next(r for r in rows if r.get('name')=='security_config')['present']=False
            if change=='platform':next(r for r in rows if r['kind']=='code-signing')['flags']='0x0'
            if change=='incomplete':phase['passed']=False
            with self.subTest(change=change),self.assertRaises(ValueError):self.validate(phase)

    def test_mach_runtime_window_requires_file_backing(self):
        data=bytearray(0x200)
        struct.pack_into('<8I',data,0,0xfeedfacf,0x100000c,0,2,1,72,0,0)
        struct.pack_into('<II16s4Q4I',data,32,0x19,72,b'__TEXT',0x1000,0x1000,0,0x200,5,5,0,0)
        self.assertEqual(mach_window(data,0x1100,32),bytes(data[0x100:0x120]))
        with self.assertRaisesRegex(ValueError,'not backed'):mach_window(data,0x11ff,2)

    @unittest.skipUnless(os.environ.get('ZETA_NATIVE_JS_EVIDENCE'),'native evidence directory not selected')
    def test_retained_physical_evidence(self):
        result=js.normalize(os.environ['ZETA_NATIVE_JS_EVIDENCE'])
        self.assertEqual(len(result['observations']),4)
        self.assertTrue(result['gcs_feature_absent_all_eight_online_guest_cpus'])
        self.assertFalse(result['live_policy_toggle_qualified'])
        self.assertFalse(result['off_again_phase_observed'])
        self.assertFalse(result['conversion_qualified'])


if __name__=='__main__':unittest.main()
