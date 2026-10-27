import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('full_stock_seed',Path(__file__).parents[1]/'make-zeta-data-seed.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class FullStockDataSeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.var=self.root/'var';self.var.mkdir()
        app=self.var/'staged_system_apps/Stock.app';app.mkdir(parents=True)
        (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.stock.app'}));(app/'Executable').write_bytes(b'app bytes')
        prefs=self.var/'mobile/Library/Preferences';prefs.mkdir(parents=True)
        (prefs/'com.apple.purplebuddy.plist').write_bytes(plistlib.dumps({'StockValue':'preserved'}))
    def tearDown(self):self.tmp.cleanup()
    def test_default_includes_every_staged_app_file(self):
        dirs,files,links,added=M.plan(self.var)
        info=self.var.stat()
        self.assertEqual(dict(dirs)['/'],(info.st_uid,info.st_gid,f'{info.st_mode & 0o7777:o}'))
        self.assertEqual(sum(f['path'].startswith('/staged_system_apps/Stock.app/') for f in files),2)
        self.assertTrue(M.full_stock_policy(files,True,None)['full_stock_compatible'])
    def test_explicit_legacy_optout_is_not_full_stock(self):
        dirs,files,links,added=M.plan(self.var,include_staged_apps=False)
        self.assertFalse(any(f['path'].startswith('/staged_system_apps/') for f in files))
        self.assertFalse(M.full_stock_policy(files,False,None)['full_stock_compatible'])
    def test_undersized_capacity_rejected_before_any_format_or_copy(self):
        dirs,files,links,added=M.plan(self.var);budget=M.capacity_budget(dirs,files)
        self.assertGreaterEqual(budget['default_size_mib'],4096)
        with self.assertRaisesRegex(ValueError,'no apps will be dropped'):M.require_capacity(64,budget)
        M.require_capacity(budget['default_size_mib'],budget)
    def test_setup_uses_source_build_and_preserves_unrelated_stock_keys(self):
        dirs,files,links,added=M.plan(self.var,scratch=self.root,setup_done=True,build='24A94425')
        bypath={f['path']:f for f in files};purple=plistlib.loads(Path(bypath['/mobile/Library/Preferences/com.apple.purplebuddy.plist']['source']).read_bytes())
        self.assertEqual(purple['StockValue'],'preserved');self.assertTrue(purple['SetupDone'])
        migration=plistlib.loads(Path(bypath['/mobile/Library/Preferences/com.apple.migration.plist']['source']).read_bytes())
        self.assertEqual(migration['LastSystemVersion'],'24A94425')
        self.assertNotIn('/mobile/Library/Preferences/com.apple.springboard.plist',bypath)
    def test_control_preference_merges_are_rejected_for_full_stock(self):
        with self.assertRaisesRegex(ValueError,'legacy rendering'):M.full_stock_policy([],True,{'CAForceSoftwareRendering':True})
    def test_new_launch_cache_override_rejected_but_stock_defaults_retained(self):
        path='/ngpu/xpc/launchd.plist'
        with self.assertRaisesRegex(ValueError,'suppression'):M.full_stock_policy([{'path':path,'origin':'owner-overlay'}],True,None)
        self.assertTrue(M.full_stock_policy([{'path':path,'origin':'stock-source'}],True,None)['full_stock_compatible'])
    def test_setup_needs_actual_source_build(self):
        with self.assertRaisesRegex(ValueError,'actual source build'):M.plan(self.var,scratch=self.root,setup_done=True)

if __name__=='__main__':unittest.main()
