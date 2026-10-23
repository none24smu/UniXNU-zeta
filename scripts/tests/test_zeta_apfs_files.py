"""The guest plan of write-zeta-apfs-files."""
import importlib.util
from pathlib import Path
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('zeta_apfs_files', SCRIPTS / 'write-zeta-apfs-files.py')
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


class PlanTests(unittest.TestCase):
    def test_new_files_are_copied_and_hashed(self):
        lines = W.plan([('/d', 0, 0, '755')], [('/d/f', 0, 0, '644')]).splitlines()
        self.assertEqual(lines[:5], ['set -e', 'SRC=$1; DST=$2', 'mkdir -p "$DST/d"', 'chown 0:0 "$DST/d"',
                                     'chmod 755 "$DST/d"'])
        self.assertIn('cp "$SRC/f0" "$DST/d/f"', lines)
        self.assertFalse(any(line.startswith('rm ') for line in lines))
        self.assertTrue(lines[-1].startswith('echo "GUEST-HASH 0 '))

    def test_replace_removes_each_target_before_the_copy(self):
        lines = W.plan([], [('/sbin/mount', 0, 0, '755'), ('/usr/bin/su', 0, 0, '4755')], replace=True).splitlines()
        for index, path in enumerate(('/sbin/mount', '/usr/bin/su')):
            removal = lines.index(f'rm -f "$DST{path}"')
            self.assertEqual(lines[removal + 1], f'cp "$SRC/f{index}" "$DST{path}"')
        self.assertIn('chmod 4755 "$DST/usr/bin/su"', lines)


if __name__ == '__main__':
    unittest.main()
