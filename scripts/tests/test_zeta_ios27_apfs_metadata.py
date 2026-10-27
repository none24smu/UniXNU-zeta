import importlib.util
from pathlib import Path
import struct
import sys
import unittest
import copy
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).parents[1]))
import zeta_ios27_apfs_metadata as M

class NativeMetadataTests(unittest.TestCase):
    def setUp(self):
        self.fields={'bsd_flags':M.COMPRESSED,'internal_flags':0}
        self.header=(2,struct.pack('<4sIQ',b'fpmc',4,123))
        self.attrs={'com.apple.decmpfs':self.header,'com.apple.ResourceFork':(1,b'fork')}
        self.expected={'kind':'file','size':123,'sha256':'ab'*32}
        self.actual={'sha256':'ab'*32}
    def test_verified_decode_can_normalize_compression_only(self):
        r=M.normalization('/file',self.fields,self.attrs,self.expected,self.actual)
        self.assertEqual(r['compression_kind'],4)
        self.assertEqual(len(r['omitted_attributes']),2)
    def test_acl_omission_is_never_compression_waiver(self):
        self.attrs['com.apple.system.Security']=(2,b'acl')
        with self.assertRaisesRegex(ValueError,'non-compression'):M.normalization('/file',self.fields,self.attrs,self.expected,self.actual)
    def test_changed_decoded_file_fails(self):
        self.actual['sha256']='cd'*32
        with self.assertRaisesRegex(ValueError,'decoded-content'):M.normalization('/file',self.fields,self.attrs,self.expected,self.actual)
    def test_uncompressed_resource_fork_is_not_discarded(self):
        self.attrs.pop('com.apple.decmpfs')
        with self.assertRaisesRegex(ValueError,'non-compression'):M.normalization('/file',self.fields,self.attrs,self.expected,self.actual)
    def test_security_ea_flag_refuses_normalization(self):
        self.fields['internal_flags']=M.HAS_SECURITY_EA
        with self.assertRaisesRegex(ValueError,'security EA'):M.normalization('/file',self.fields,self.attrs,self.expected,self.actual)
    def test_wrong_resource_fork_kind_fails(self):
        self.attrs['com.apple.decmpfs']=(2,struct.pack('<4sIQ',b'fpmc',3,123))
        with self.assertRaisesRegex(ValueError,'recognized compression'):M.normalization('/file',self.fields,self.attrs,self.expected,self.actual)
    def test_actual27_lzbitmap_resource_format_is_explicitly_supported(self):
        self.attrs['com.apple.decmpfs']=(2,struct.pack('<4sIQ',b'fpmc',14,123))
        self.assertEqual(M.normalization('/file',self.fields,self.attrs,self.expected,self.actual)['compression_kind'],14)
    def test_native_inode_offsets(self):
        b=bytearray(92);struct.pack_into('<4Q',b,16,1,2,3,4);struct.pack_into('<Q',b,48,64)
        struct.pack_into('<5I',b,60,7,8,9,501,20);struct.pack_into('<H',b,80,0o100644)
        f=M.inode_fields(b);self.assertEqual(f['times_ns'],[1,2,3,4]);self.assertEqual(f['bsd_flags'],9)
        self.assertEqual((f['protection_class'],f['uid'],f['gid'],f['mode']),(7,501,20,0o100644))
    def test_file_extent_cannot_change_following_inode_node_location(self):
        b=bytearray(4096);struct.pack_into('<HHI',b,32,2,0,3);struct.pack_into('<HH',b,40,0,24)
        keys=[struct.pack('<Q',3|(3<<60)),struct.pack('<QQ',3|(8<<60),0),struct.pack('<Q',4|(3<<60))]
        vals=[bytes(92),struct.pack('<QQQ',4096,999,0),bytes(92)];ko=0;vo=0
        for i,(key,value) in enumerate(zip(keys,vals)):
            vo+=len(value);struct.pack_into('<4H',b,56+8*i,ko,len(key),vo,len(value))
            b[80+ko:80+ko+len(key)]=key;b[4096-vo:4096-vo+len(value)]=value;ko+=len(key)
        c=SimpleNamespace(block_size=4096,omap_lookup=lambda *a:42,block=lambda n:bytes(b),valid=lambda b:True)
        cat=M.Catalog(SimpleNamespace(container=c,root_tree=2,omap_root=0,xid=1))
        self.assertEqual(cat.inodes[4][1],42);self.assertEqual(cat.extents[3][0][2],999)
    def test_sealed_noheader_node_requires_explicit_sealed_source(self):
        b=bytearray(4096);struct.pack_into('<HHI',b,32,0x1b,0,0)
        c=SimpleNamespace(block_size=4096,omap_lookup=lambda *a:42,block=lambda n:bytes(b),valid=lambda b:False)
        v=SimpleNamespace(container=c,root_tree=2,omap_root=0,xid=1,incompatible=0x20)
        self.assertEqual(len(M.Catalog(v).sealed_noheader_nodes),1)
        v.incompatible=0
        with self.assertRaisesRegex(ValueError,'unexpected no-header'):M.Catalog(v)
    def qualified_fixture(self):
        entry=dict(kind='file',mode=0o644,uid=0,gid=0,mtime_ns=10,size=123,sha256='ab'*32,
                   xattrs={'com.apple.decmpfs':{'bytes':16,'sha256':'cd'*32}})
        source={'inventory_complete':True,'roots':{'data':{'namespace_prefix':'/private/var','entries':{'/file':entry},'services':[],'bundles':[]}}}
        candidate=copy.deepcopy(source);candidate['roots']['data']['entries']['/file']['xattrs']={}
        report=dict(native_fixed_metadata_readback_passed=True,critical_xattrs_lost=[],security_ea_loss=False,restored_inodes=1,
            compression_normalizations=[dict(path='/file',decoded_sha256='ab'*32,omitted_attributes=['com.apple.decmpfs'])])
        return source,candidate,report
    def test_normalized_gate_accepts_only_exact_decoded_transform(self):
        s,c,r=self.qualified_fixture();self.assertTrue(M.qualify(s,c,r)['normalized_file_metadata_qualified'])
    def test_normalized_gate_does_not_cover_added_acl_on_compressed_file(self):
        s,c,r=self.qualified_fixture();c['roots']['data']['entries']['/file']['xattrs']['com.apple.system.Security']={'bytes':4,'sha256':'ef'*32}
        self.assertFalse(M.qualify(s,c,r)['normalized_file_metadata_qualified'])

if __name__=='__main__':unittest.main()
