"""Reference identities and read-only x1 parsing must not enable conversion."""
import importlib.util
from pathlib import Path
import struct,subprocess,sys,tempfile,tomllib,unittest

SCRIPTS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SCRIPTS))
import zeta_dyld_cache as dc
spec=importlib.util.spec_from_file_location('adt',SCRIPTS/'make-zeta-adt.py')
adt=importlib.util.module_from_spec(spec);spec.loader.exec_module(adt)
spec=importlib.util.spec_from_file_location('rewrite',SCRIPTS/'rewrite-zeta-userland.py')
rewrite=importlib.util.module_from_spec(spec);spec.loader.exec_module(rewrite)

class IdentityTests(unittest.TestCase):
    def test_control_identity_is_unchanged(self):
        model,target,product=adt.identity_values('iPhone18,2')
        self.assertEqual((model,target,product),(adt.MODEL,adt.TARGET_TYPE,adt.PRODUCT))
    def test_duo_reference_fields_and_real_hardware_separation(self):
        model,target,product=adt.identity_values('iPhone19,4');p=dict(product)
        self.assertEqual((model,target),(b'iPhone19,4\0',b'V68\0'))
        self.assertEqual(p['product-name'],b'iPhone Duo\0')
        self.assertEqual(struct.unpack('<I',p['artwork-device-subtype'])[0],2034)
        self.assertEqual(p['app-macho-architecture'],b'arm64e.x1\0')
        self.assertEqual(p['sub-product-type'],model)
        self.assertNotIn('graphics-featureset-class',p)
        self.assertEqual(adt.BOARD_COMPATIBLE,b'qcom,lahaina-mtp\0qcom,lahaina\0')
        self.assertEqual((adt.GIC_DIST,adt.TIMEBASE),(0x17a00000,19200000))
    def test_unknown_identity_refused(self):
        with self.assertRaises(ValueError):adt.identity_values('unverified')
    def test_payload_entrypoint_generates_v68_without_changing_hardware(self):
        # Exercise the exact board.toml tool; the generic payload builder does
        # not forward an identity_profile key, so testing only the helper would
        # miss a silently generated V54 tree.
        board=tomllib.loads((SCRIPTS.parent/'board.toml').read_text())
        def unpack(blob,at=0):
            count,children=struct.unpack_from('<II',blob,at);at+=8;props={}
            for _ in range(count):
                key,length=struct.unpack_from('<32sI',blob,at);at+=36
                props[key.split(b'\0')[0].decode()]=blob[at:at+length];at+=(length+3)&~3
            nodes={}
            for _ in range(children):
                child,at=unpack(blob,at);nodes[child[0]['name'].rstrip(b'\0').decode()]=child
            return (props,nodes),at
        with tempfile.TemporaryDirectory() as d:
            outputs=[]
            for tool in ['scripts/make-zeta-adt.py',board['payload']['adt']['tool']]:
                out=Path(d)/str(len(outputs))
                subprocess.run([sys.executable,str(SCRIPTS.parent/tool),'--output',str(out),
                                '--dram-size',board['payload']['dram_size']],check=True,capture_output=True)
                outputs.append(unpack(out.read_bytes())[0])
            control,target=outputs
        self.assertEqual(target[0]['model'],b'iPhone19,4\0')
        self.assertEqual(target[0]['target-type'],b'V68\0')
        self.assertEqual(target[0]['target-sub-type'],b'V68AP\0')
        self.assertEqual(target[1]['product'][0]['product-name'],b'iPhone Duo\0')
        for name in ['cpus','psci','arm-io','buttons','defaults','options']:
            self.assertEqual(control[1][name],target[1][name])
        self.assertEqual(control[0]['compatible'],target[0]['compatible'])
        self.assertEqual(target[1]['product'][0]['model'],b'Surface Duo2 MP\0')
        self.assertEqual(board['ipsw']['product'],'iPhone19,4')
        self.assertEqual(board['ipsw']['device_class'],'v68ap')

class CacheArchitectureTests(unittest.TestCase):
    def test_x1_executable_conversion_remains_disabled(self):
        header=struct.pack('<8I',0xfeedfacf,0x100000c,0x8000000c,2,0,0,0,0)
        with self.assertRaisesRegex(ValueError,'analysis-only'):
            rewrite.rewrite(header)
    def cache(self,magic):
        data=bytearray(512);data[:16]=magic.ljust(16,b'\0')
        return data
    def test_existing_cache_default_still_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cache';p.write_bytes(self.cache(b'dyld_v1  arm64e'))
            f=dc.CacheFile(p)
            try:self.assertEqual(f.architecture,'arm64e')
            finally:f.data.close();f.handle.close()
    def test_x1_requires_explicit_analysis_option(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cache';p.write_bytes(self.cache(b'dyld_v1arm64ex1'))
            with self.assertRaisesRegex(ValueError,'analysis-only'):dc.CacheFile(p)
            f=dc.CacheFile(p,allow_x1_analysis=True)
            try:self.assertEqual(f.architecture,'arm64e.x1')
            finally:f.data.close();f.handle.close()
    def test_unrelated_magic_refused_even_with_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cache';p.write_bytes(self.cache(b'dyld_v1  x86_64'))
            with self.assertRaisesRegex(ValueError,'unsupported'):dc.CacheFile(p,allow_x1_analysis=True)

if __name__=='__main__':unittest.main()
