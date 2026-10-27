import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tarfile
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('payload_inventory',Path(__file__).parents[1]/'zeta_ios27_payload_inventory.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class PayloadInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);self.root=self.base/'root';self.root.mkdir()
        for path,identifier in [('Applications/Stock.app','com.stock.app'),
                ('Applications/Stock.app/PlugIns/Widget.appex','com.stock.widget'),
                ('Applications/Stock.app/XPCServices/Worker.xpc','com.stock.worker')]:
            folder=self.root/path;folder.mkdir(parents=True)
            (folder/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':identifier,'CFBundleExecutable':'Executable'}))
            (folder/'Executable').write_bytes(b'original executable '+identifier.encode());(folder/'Executable').chmod(0o755)
        daemon=self.root/'System/Library/LaunchDaemons';daemon.mkdir(parents=True)
        self.service=daemon/'com.stock.app.plist';self.service.write_bytes(plistlib.dumps({'Label':'com.stock.app',
            'Program':'/bin/stock','RunAtLoad':True,'MachServices':{'com.stock.endpoint':True}}))
        (self.root/'bin').mkdir();(self.root/'bin/stock').symlink_to('/Applications/Stock.app/Executable')
        data=self.root/'Applications/Stock.app/data';data.write_bytes(b'content');os.link(data,data.with_name('data2'))
        pref=self.root/'private/var/mobile/Library/Preferences';pref.mkdir(parents=True)
        self.pref=pref/'com.apple.purplebuddy.plist';self.pref.write_bytes(plistlib.dumps({'KeepStockKey':'yes'}))
    def tearDown(self):self.tmp.cleanup()
    def scan(self):return M.inventory({'main':self.root})
    def test_all_bundle_kinds_and_virtual_absolute_symlink(self):
        source=self.scan();volume=source['roots']['main']
        self.assertTrue(source['inventory_complete']);self.assertEqual({b['kind'] for b in volume['bundles']},{'.app','.appex','.xpc'})
        self.assertEqual(volume['services'][0]['program_sources'],[{'root':'main','path':'/Applications/Stock.app/Executable','kind':'file'}])
    def test_complete_archive_preserves_every_content_and_posix_entry(self):
        os.setxattr(self.root/'Applications/Stock.app/data','user.stock',b'attribute data')
        source=self.scan();archive=self.base/'full.tar';M.stage_archive(source['roots']['main'],archive)
        candidate=M.inventory({},archives={'main':archive});result=M.compare(source,candidate)
        self.assertTrue(result['stock_payload_complete'],result['failures'])
        self.assertTrue(result['observed_metadata_identical'],result['metadata_warnings'])
        self.assertFalse(result['native_metadata_qualified'])
        self.assertFalse(result['deployment_ready']);self.assertFalse(result['runtime_verified'])
    def test_missing_stock_app_member_blocks_gate(self):
        source=self.scan();(self.root/'Applications/Stock.app/data').unlink();result=M.compare(source,self.scan())
        self.assertFalse(result['stock_payload_complete']);self.assertTrue(any(x['reason']=='missing-stock-entry' for x in result['failures']))
    def test_disabled_stock_service_blocks_even_with_setup_option(self):
        source=self.scan();value=plistlib.loads(self.service.read_bytes());value['Disabled']=True
        self.service.write_bytes(plistlib.dumps(value));result=M.compare(source,self.scan(),True)
        self.assertTrue(any(x['reason']=='stock-service-removed-or-modified' for x in result['failures']))
    def test_permission_change_blocks_gate(self):
        source=self.scan();(self.root/'Applications/Stock.app/Executable').chmod(0o644)
        self.assertTrue(any(x.get('field')=='mode' for x in M.compare(source,self.scan())['failures']))
    def test_symlink_target_change_blocks_gate(self):
        source=self.scan();link=self.root/'bin/stock';link.unlink();link.symlink_to('/host/private/data')
        self.assertTrue(any(x.get('field')=='target' for x in M.compare(source,self.scan())['failures']))
    def test_exact_setup_preferences_can_change_without_weakening_services(self):
        source=self.scan();self.pref.write_bytes(plistlib.dumps({'KeepStockKey':'yes','SetupDone':True}))
        candidate=self.scan();self.assertFalse(M.compare(source,candidate)['stock_payload_complete'])
        self.assertTrue(M.compare(source,candidate,True)['stock_payload_complete'])
    def test_missing_hashes_cannot_certify_content(self):
        source=M.inventory({'main':self.root},hash_files=False)
        self.assertFalse(M.compare(source,source)['stock_payload_complete'])
    def test_archive_traversal_is_rejected_without_extraction(self):
        archive=self.base/'unsafe.tar'
        with tarfile.open(archive,'w') as stream:stream.addfile(tarfile.TarInfo('../outside'))
        with self.assertRaises(ValueError):M.inventory({},archives={'main':archive})
        self.assertFalse((self.base/'outside').exists())
    def test_missing_cryptex_root_blocks_gate(self):
        source=self.scan();candidate=dict(source,roots={})
        self.assertTrue(any(x['reason']=='missing-root' for x in M.compare(source,candidate)['failures']))
    def test_explicit_cryptex_namespace_resolves_cross_root_symlinks(self):
        app=self.base/'app';(app/'usr/libexec').mkdir(parents=True);(app/'usr/libexec/stock').write_bytes(b'app executable')
        value=plistlib.loads(self.service.read_bytes());value['Program']='/System/Cryptexes/App/usr/libexec/stock'
        self.service.write_bytes(plistlib.dumps(value))
        result=M.inventory({'main':self.root,'app':app},namespaces={'app':'/System/Cryptexes/App'})
        self.assertEqual(result['roots']['main']['services'][0]['program_sources'],[{'root':'app','path':'/usr/libexec/stock','kind':'file'}])
    def test_extra_launchd_disabled_file_blocks_full_stock(self):
        source=self.scan();f=self.root/'private/var/db/com.apple.xpc.launchd/disabled.plist';f.parent.mkdir(parents=True)
        f.write_bytes(plistlib.dumps({'com.stock.app':True}));result=M.compare(source,self.scan(),True)
        self.assertTrue(any(x['reason']=='new-or-mutated-launchd-suppression-override' for x in result['failures']))
    def test_extra_ngpu_launchcache_blocks_full_stock(self):
        source=self.scan();f=self.root/'private/var/ngpu/xpc/launchd.plist';f.parent.mkdir(parents=True)
        f.write_bytes(plistlib.dumps({'control-cache':True}));result=M.compare(source,self.scan())
        self.assertTrue(any(x['reason']=='new-or-mutated-launchd-suppression-override' for x in result['failures']))
    def test_unrelated_springboard_rendering_mutation_is_not_setup_skip(self):
        f=self.pref.with_name('com.apple.springboard.plist');f.write_bytes(plistlib.dumps({'CAForceSoftwareRendering':False}))
        source=self.scan();f.write_bytes(plistlib.dumps({'CAForceSoftwareRendering':True}));result=M.compare(source,self.scan(),True)
        self.assertFalse(result['stock_payload_complete'])
    def test_wrong_setup_value_is_not_exempted(self):
        source=self.scan();self.pref.write_bytes(plistlib.dumps({'KeepStockKey':'yes','SetupVersion':99}))
        self.assertFalse(M.compare(source,self.scan(),True)['stock_payload_complete'])
    def test_legacy_suppression_bootargs_rejected(self):
        source=self.scan()
        for option in ['sheng-lite=1','sheng-disable-jobs=service','sheng-lite=0']:
            result=M.compare(source,source,boot_args=option)
            self.assertFalse(result['stock_payload_complete']);self.assertFalse(result['full_stock_boot_policy_pass'])
        self.assertTrue(M.compare(source,source,boot_args='-v')['full_stock_boot_policy_pass'])
        self.assertIsNone(M.compare(source,source)['full_stock_boot_policy_pass'])
    def test_minimal_setup_overlay_uses_new_build_and_no_control_preferences(self):
        f=self.root/'System/Library/CoreServices/SystemVersion.plist';f.parent.mkdir(parents=True)
        f.write_bytes(plistlib.dumps({'ProductVersion':'27.1','ProductBuildVersion':'24A94425'}))
        output=self.base/'setup';report=M.write_setup_overlay(self.root,output)
        self.assertEqual(report['build'],'24A94425');self.assertEqual(len(report['files']),3)
        self.assertEqual(report['stock_service_changes'],[])
        self.assertFalse((output/'mobile/Library/Preferences/com.apple.springboard.plist').exists())
        purple=plistlib.loads((output/'mobile/Library/Preferences/com.apple.purplebuddy.plist').read_bytes())
        self.assertEqual(purple,dict(SetupDone=True,SetupFinishedAllSteps=True,SetupVersion=11,daemonizeNeedsToRun=False))
    def test_extra_data_root_cannot_smuggle_springboard_render_state(self):
        source=self.scan();data=self.base/'data';f=data/'mobile/Library/Preferences/com.apple.springboard.plist';f.parent.mkdir(parents=True)
        f.write_bytes(plistlib.dumps({'CAForceSoftwareRendering':True}))
        candidate=M.inventory({'main':self.root,'data':data})
        self.assertTrue(any(x['reason']=='extra-root-unverified-setup-preference-state' for x in M.compare(source,candidate,True)['failures']))
    def test_candidate_extra_duplicate_label_job_cannot_override_stock_service(self):
        source=self.scan();extra=self.service.with_name('new-override.plist')
        extra.write_bytes(plistlib.dumps({'Label':'com.stock.app','Disabled':True}))
        self.assertTrue(any(x['reason']=='unreviewed-extra-launchd-service' for x in M.compare(source,self.scan())['failures']))
    def test_explicit_legacy_data_seed_rejected_by_full_stock_gate(self):
        source=self.scan();report={'full_stock_compatible':False,'included_staged_system_apps':False}
        self.assertTrue(any(x['reason']=='reduced-or-unverified-data-seed-profile' for x in M.compare(source,source,data_seed_report=report)['failures']))
    def test_fresh_data_timestamp_option_cannot_weaken_os_root(self):
        source=self.scan();f=self.root/'Applications/Stock.app/Executable';os.utime(f,ns=(1,2));candidate=self.scan()
        self.assertFalse(M.compare(source,candidate,fresh_data_timestamps=True)['stock_payload_complete'])
        source['roots']['main']['namespace_prefix']='/private/var';candidate['roots']['main']['namespace_prefix']='/private/var'
        result=M.compare(source,candidate,fresh_data_timestamps=True)
        self.assertTrue(result['stock_payload_complete']);self.assertFalse(result['observed_metadata_identical'])

if __name__=='__main__':unittest.main()
