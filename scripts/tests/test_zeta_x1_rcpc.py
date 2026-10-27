"""Reject partial function rewrites and independent interior entry points."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

SCRIPTS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SCRIPTS))
import zeta_x1_rcpc as rcpc


class Cache:
    def __init__(self):
        self.words={root:struct.pack('<'+'I'*len(words),*words) for root,_,words in rcpc.FUNCTIONS}
        self.files=[type('File',(),{'data':b'\0'*0x58+bytes.fromhex(rcpc.CACHE_UUID)})()]
    def read(self,address,size):
        return self.words[address][:size] if address in self.words else b'\0'*size


class Image:
    path=rcpc.IMAGE
    address=0x197200000
    sections=[{'name':'__unwind_info','addr':0x1000,'size':8}]
    def roots(self):
        roots={p for r,_,w in rcpc.FUNCTIONS for p in (r,r+len(w)*4)}
        return roots,set(),roots


def plans(**kwargs):
    proven={pc:'unwind' for r,_,w in rcpc.FUNCTIONS for pc in range(r,r+len(w)*4,4)}
    args=dict(cache=Cache(),image=Image(),proven=proven,incoming=[],pointers=set(),landing_pads=set(),tables=[])
    args.update(kwargs)
    with patch.object(rcpc.code,'unwind_lsdas',return_value={}):
        return rcpc.plan(**args)


def rows(groups):
    return np.array([[g['root']+i*4,0x200+i*4,a,b,0] for g in groups
                     for i,(a,b) in enumerate(zip(g['original_words'],g['translated_words'])) if a!=b],dtype=np.uint64)


class FunctionTests(unittest.TestCase):
    def test_exact_three_function_fingerprints_and_size(self):
        groups=plans()
        self.assertEqual(len(groups),3)
        for group in groups:
            self.assertEqual(len(group['original_words']),len(group['translated_words']))
            self.assertTrue(group['frame_and_unwind_positions_unchanged'])
            self.assertNotIn(0xd9410008,group['translated_words'])
            self.assertNotIn(0xd9408100,group['translated_words'])
            for i in range(len(group['original_words'])):
                changed=group['original_words'].copy();changed[i]^=1
                with self.assertRaisesRegex(ValueError,'fingerprint'):
                    rcpc.translate(group['root'],group['kind'],changed)

    def test_effective_addresses_and_original_slow_target_preserved(self):
        release=plans()[0];words=release['translated_words'];root=release['root']
        self.assertEqual(words[0],0x91004010)  # ADD X16,X0,#16
        self.assertEqual(words[1],0xc8dffe08)  # LDAR X8,[X16]
        self.assertEqual((words[4]>>5)&31,16)  # LDADDAL same X16 address
        target=root+8+(((words[2]>>5)&0x7ffff)*4)
        self.assertEqual(target,root+28)
        for group in plans()[1:]:
            w=group['translated_words'];self.assertEqual(w[11:13],[0x91002100,0xc8dffc00])
            original=group['original_words']
            self.assertEqual([w[i] for i in [1,2,3,4,5,13,14]],[original[i] for i in [1,2,3,4,5,13,14]])
            imm=w[6]&0x3ffffff;imm-=1<<26 if imm&(1<<25) else 0
            self.assertEqual(group['root']+24+imm*4,0x19725be24)

    def test_independent_interior_entry_pointer_landing_or_table_rejected(self):
        root=rcpc.FUNCTIONS[0][0]
        variants=[{'incoming':[{'source':root-4,'target':root+4}]},
                  {'incoming':[{'source':root,'target':root+4,'kind':'materialized-address'}]},
                  {'pointers':{root+4}}, {'landing_pads':{root+4}},
                  {'tables':[{'targets':[root+4]}]}]
        for kwargs in variants:
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):plans(**kwargs)
        self.assertEqual(len(plans(incoming=[{'source':root+4,'target':root+28}])),3)

    def test_wrong_cache_uuid_unproven_word_and_lsda_rejected(self):
        cache=Cache();cache.files[0].data=b'\0'*0x68
        with self.assertRaisesRegex(ValueError,'UUID'):plans(cache=cache)
        with self.assertRaisesRegex(ValueError,'unproven'):plans(proven={})
        with patch.object(rcpc.code,'unwind_lsdas',return_value={rcpc.FUNCTIONS[0][0]:0x2000}):
            proven={pc:'unwind' for r,_,w in rcpc.FUNCTIONS for pc in range(r,r+len(w)*4,4)}
            with self.assertRaisesRegex(ValueError,'LSDA'):
                rcpc.plan(Cache(),Image(),proven,[],set(),set())

    def test_targeted_scan_finds_branches_and_materialized_interior_addresses(self):
        source=0x100000;root=source+0x1000
        # ADR X8,root+4; ADRP X9,root; ADD X9,X9,#8; B root+12.
        delta=root+4-source
        adr=0x10000008|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)
        data=struct.pack('<4I',adr,rcpc.adrp(source+4,root,9),0x91002129,rcpc.direct_branch(source+12,root+12))
        class ScanCache:
            images=[(source,'fixture')]
            files=[type('File',(),{'data':data})()]
            def locate(self,address):return 0,address-source,len(data)-(address-source)
        class ScanImage:
            def __init__(self,*args):pass
            def instruction_sections(self):return [{'addr':source,'size':len(data)}]
        import zeta_dyld_cache
        with patch.object(zeta_dyld_cache,'Image',ScanImage):
            found=rcpc.incoming_transfers(ScanCache(),[(root,root+16)])
        self.assertEqual({(r['kind'],r['target']) for r in found},{('branch',root+12),('materialized-address',root+4),('materialized-address',root+8)})

    def test_coordinated_rows_reject_partial_or_mutated_groups(self):
        groups=plans();edits=rows(groups)
        self.assertEqual(len(rcpc.group_edits(groups,edits)),len(edits))
        for changed in [edits[:-1],np.concatenate([edits,edits[:1]])]:
            with self.assertRaises(ValueError):rcpc.group_edits(groups,changed)
        changed=edits.copy();changed[0,3]=int(changed[0,3])^1
        with self.assertRaisesRegex(ValueError,'mismatched'):rcpc.group_edits(groups,changed)
        for field in ['translated_words','original_sha256','independent_interior_entry_absent']:
            bad=copy.deepcopy(groups)
            if field=='translated_words':bad[0][field][0]^=1
            else:bad[0][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):rcpc.group_edits(bad,edits)
        with self.assertRaisesRegex(ValueError,'incomplete'):rcpc.group_edits(groups[:1],edits)

    def test_writer_does_not_accept_coordinated_rows_as_single_words(self):
        spec=importlib.util.spec_from_file_location('rcpc_cache_rewrite',SCRIPTS/'rewrite-zeta-dyld-cache.py')
        rewrite=importlib.util.module_from_spec(spec);spec.loader.exec_module(rewrite)
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);path=directory/'rows.npz';groups=plans();edits=rows(groups)
            np.savez(path,edits=edits)
            entry={'edit_count':len(edits),'result_file':path.name,'result_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'file':0,'rcpc2_function_aot':groups}
            summary={'experimental_profile':'test','images':{rcpc.IMAGE:entry},'islands':[]}
            with self.assertRaisesRegex(ValueError,'explicit typed AOT contract'):rewrite.load_edits(directory,summary)
            with self.assertRaisesRegex(ValueError,'not explicitly enabled'):rewrite.load_edits(directory,summary,{'policy':{}})
            del entry['rcpc2_function_aot']
            with self.assertRaisesRegex(ValueError,'nonqualified lowering'):rewrite.load_edits(directory,summary)


if __name__=='__main__':unittest.main()
