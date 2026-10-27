from pathlib import Path
import os
import struct
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).parents[1]/'zeta_stock_tree_copy.cpp'

class RootCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory();cls.exe=Path(cls.build.name)/'copy'
        subprocess.run(['clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(SOURCE),'-o',str(cls.exe)],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.build.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);self.source=self.base/'source';self.target=self.base/'target'
        self.source.mkdir();self.target.mkdir()
    def tearDown(self):self.tmp.cleanup()
    def run_copy(self,*args):return subprocess.run([str(self.exe),*map(str,args)],capture_output=True,text=True)
    def plan(self,pairs):
        path=self.base/'links.bin';b=bytearray(struct.pack('<8sQ',b'ZHLINK01',len(pairs)))
        for pair in pairs:
            for p in pair:q=p.encode();b+=struct.pack('<I',len(q))+q
        path.write_bytes(b);return path
    def test_full_tree_bytes_modes_symlink_and_hardlink(self):
        d=self.source/'folder $ with space';d.mkdir();p=d/'a\nfile';p.write_bytes(b'full bytes\0'*100);p.chmod(0o640)
        (d/'alias').hardlink_to(p);(self.source/'link').symlink_to('/outside/source-must-not-follow')
        r=self.run_copy(self.source,self.target);self.assertEqual(r.returncode,0,r.stderr)
        t=self.target/d.name;self.assertEqual((t/p.name).read_bytes(),p.read_bytes());self.assertEqual((t/p.name).stat().st_ino,(t/'alias').stat().st_ino)
        self.assertEqual((t/p.name).stat().st_mode&0o7777,0o640);self.assertEqual(os.readlink(self.target/'link'),'/outside/source-must-not-follow')
    def test_nonempty_target_refused_without_overwrite(self):
        (self.target/'keep').write_text('keep');r=self.run_copy(self.source,self.target)
        self.assertNotEqual(r.returncode,0);self.assertEqual((self.target/'keep').read_text(),'keep')
    def test_native_plan_repairs_hidden_links(self):
        (self.target/'a').write_text('same');(self.target/'b').write_text('same')
        r=self.run_copy('--repair-hardlinks',self.plan([('a','b')]),self.target)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual((self.target/'a').stat().st_ino,(self.target/'b').stat().st_ino)
    def test_native_plan_cannot_escape_through_parent_symlink(self):
        outside=self.base/'outside';outside.mkdir();(outside/'b').write_text('same')
        (self.target/'a').write_text('same');(self.target/'escape').symlink_to(outside,target_is_directory=True)
        r=self.run_copy('--repair-hardlinks',self.plan([('a','escape/b')]),self.target)
        self.assertNotEqual(r.returncode,0);self.assertEqual((outside/'b').read_text(),'same')
    def test_unhandled_source_type_is_not_silently_dropped(self):
        os.mkfifo(self.source/'fifo');r=self.run_copy(self.source,self.target)
        self.assertNotEqual(r.returncode,0);self.assertIn('unsupported stock entry',r.stderr)

if __name__=='__main__':unittest.main()
