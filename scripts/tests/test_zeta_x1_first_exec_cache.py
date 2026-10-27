"""Diagnostic cache selection preserves unproven aliases and nonowned bytes."""
import importlib.util
from pathlib import Path
import sys
import unittest

import numpy as np

SCRIPTS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SCRIPTS))
spec=importlib.util.spec_from_file_location('first_exec_cache',SCRIPTS/'prepare-zeta-x1-first-exec-cache.py')
cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cache)
import zeta_x1_compat as x1
import zeta_userland_pauth as pauth


class CacheDiagnosticTests(unittest.TestCase):
    def test_conflicting_edits_fail_and_unproven_alias_is_never_written(self):
        rows=np.array([[4,1,2],[0,3,4],[4,1,2],[8,5,6]],dtype=np.uint64)
        result,duplicates,dropped=cache.canonical(rows,np.array([4],dtype=np.uint64))
        self.assertEqual(result.tolist(),[[0,3,4],[8,5,6]])
        self.assertEqual((duplicates,dropped),(1,1))
        rows[2,2]=7
        with self.assertRaisesRegex(ValueError,'conflicting'):cache.canonical(rows,np.zeros(0,dtype=np.uint64))

    def test_each_frozen_replacement_must_match_exact_known_selector(self):
        original=0xdac10000;ordinary=pauth.lower(original)[1]
        rows=np.array([[0x1000,0x200,original,ordinary,0]],dtype=np.uint64)
        cache.exact_lowerings(rows,x1,pauth,{})
        rows[0,3]=int(rows[0,3])^1
        with self.assertRaisesRegex(ValueError,'differs'):cache.exact_lowerings(rows,x1,pauth,{})
        rows[0,2]=0xffffffff
        with self.assertRaisesRegex(ValueError,'unknown'):cache.exact_lowerings(rows,x1,pauth,{})

    def test_whole_body_identity_outside_declared_edits(self):
        original=bytearray(4096);changed=bytearray(original);changed[0x200:0x204]=b'EDIT'
        table=np.array([[0x200,0,int.from_bytes(b'EDIT','little')]],dtype=np.uint64)
        self.assertEqual(cache.verify_owned_body(original,changed,table,[],4096),1)
        changed[0x180]=1
        with self.assertRaisesRegex(ValueError,'outside exact'):cache.verify_owned_body(original,changed,table,[],4096)


if __name__=='__main__':unittest.main()
