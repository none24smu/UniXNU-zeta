"""First-exec is a separate exact-input experiment, not a relaxed release gate."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SCRIPTS))


def module(name,file):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/file)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


first=module('first_exec','prepare-zeta-x1-first-exec.py')
rebind=module('first_exec_rebind','rebind-zeta-first-exec-kernel.py')


class FirstExecTests(unittest.TestCase):
    def test_unknown_path_and_wrong_input_never_enter_mechanical_writer(self):
        with self.assertRaisesRegex(ValueError,'only exact'):first.candidate(b'bad','usr/lib/other',{})
        for path in first.INPUTS:
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'fingerprint'):
                first.candidate(b'bad',path,{})

    def test_actual_mach_object_relocations_and_nonrelocation_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);source=directory/'unit.c';obj=directory/'unit.o'
            source.write_text('extern long dependency(long); long zeta_user_instruction_compat(long x){return dependency(x)+3;}\n')
            subprocess.run([shutil.which('clang'),'-target','arm64-apple-ios26.0','-ffreestanding','-mgeneral-regs-only','-O1','-c',str(source),'-o',str(obj)],check=True,capture_output=True)
            function=rebind.object_functions(obj.read_bytes(),['_zeta_user_instruction_compat'])['_zeta_user_instruction_compat']
            original=function['bytes'];self.assertTrue(function['relocation_byte_offsets'])
            self.assertEqual(rebind.compare_function(function,original),len(original)-len(function['relocation_byte_offsets']))
            changed=bytearray(original)
            at=next(i for i in range(len(changed)) if i not in function['relocation_byte_offsets'])
            changed[at]^=1
            with self.assertRaisesRegex(ValueError,'outside declared'):rebind.compare_function(function,changed)
            with self.assertRaisesRegex(ValueError,'size mismatch'):rebind.compare_function(function,original[:-1])
            with self.assertRaisesRegex(ValueError,'missing/duplicate'):rebind.object_functions(obj.read_bytes(),['_not_present'])


if __name__=='__main__':unittest.main()
