import importlib.util
from pathlib import Path
import unittest

S=importlib.util.spec_from_file_location('profile',Path(__file__).parents[1]/'check-zeta-ios27-storage-profile.py')
M=importlib.util.module_from_spec(S);S.loader.exec_module(M)

class ProfileTests(unittest.TestCase):
    def test_default_disabled_cannot_change_cpu26_build(self):
        r=M.check(False);self.assertFalse(r['profile_enabled']);self.assertEqual(r['kern_exec_defines'],['-DXNU_IOS27_CRYPTEXES=0'])
        self.assertEqual(r['helper_objects_required'],[])
    def test_enabled_profile_requires_evidence(self):
        with self.assertRaises(ValueError):M.check(True)
    def test_retarget_preserves_real_abi_flags(self):
        c=M.retarget(['clang','-target','arm64-apple-ios26.0','-DKDK_IOKIT_ABI=1','-c','old.cpp','-o','old.o','-MF','old.d'],'old.cpp','new.cpp','new.o',['-I','profile'])
        self.assertIn('-DKDK_IOKIT_ABI=1',c);self.assertIn('arm64-apple-ios26.0',c);self.assertNotIn('old.cpp',c)
        self.assertNotIn('-MF',c);self.assertEqual(c[-2:],['-I','profile'])

if __name__=='__main__':unittest.main()
