"""Runtime captures must not retain a normal boot timeout/reset branch."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load('runtime_probe', SCRIPTS / 'patch-zeta-kernel-probe.py')


class ModeTests(unittest.TestCase):
    def test_runtime_mode_refuses_a_timer_or_disabled_native_exceptions(self):
        options = dict(fault_guards_only=True, guard_early_faults=True,
                       allow_interrupts=True, allow_vm_faults=True,
                       allow_user_exceptions=True, poll_native_usb=True, log_faults=True)
        for changed in ({'reset_delay': 300}, {'sleep_poll_ms': 20},
                        {'allow_user_exceptions': False}, {'reset_before': True}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'Fault-guards-only'):
                P.prepare(Path('/unused'), Path('/unused-output'), **(options | changed))


@unittest.skipUnless(os.environ.get('ZETA_RUNTIME_KERNEL'), 'supply actual unprobed runtime kernel')
class ActualKernelTests(unittest.TestCase):
    def test_original_call_is_preserved_and_only_fault_guards_are_reachable(self):
        M = load('runtime_macho', SCRIPTS / 'audit-zeta-apfs.py')
        original_path = Path(os.environ['ZETA_RUNTIME_KERNEL'])
        original = M.MachO(original_path.read_bytes(), original_path)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'kernel.macho'
            result = subprocess.run(['python3', str(SCRIPTS / 'patch-zeta-kernel-probe.py'), str(original_path),
                                     '--output', str(output), '--stage', 'arm-init', '--in', '_bsdinit_task',
                                     '--reset-after', '_load_init_program', '--guard-early-faults',
                                     '--allow-interrupts', '--allow-vm-faults', '--allow-user-exceptions',
                                     '--poll-native-usb', '--log-faults', '--fault-guards-only'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.with_suffix('.macho.probe.json').read_text())
            data = output.read_bytes()
        site = original.file_at(int(report['patched_site_va'], 16), 4)
        self.assertEqual(data[site:site + 4], original.data[site:site + 4])
        self.assertEqual(struct.unpack_from('<I', data, site)[0] & 0xfc000000, 0x94000000)
        self.assertFalse(report['normal_timeout_enabled'])
        self.assertFalse(report['normal_probe_site_active'])
        self.assertIsNone(report['reset_delay_seconds'])
        self.assertTrue(report['native_el0_synchronous_vector_preserved'])
        cave = int(report['probe_va'], 16)
        allowed = [(original.file_at(cave, 512), 512)]
        for address in report['early_fault_guard_sites']:
            pc = int(address, 16)
            at = original.file_at(pc, 4)
            word = struct.unpack_from('<I', data, at)[0]
            self.assertEqual(word & 0xfc000000, 0x14000000)
            delta = word & 0x3ffffff
            if delta & 0x2000000:
                delta -= 0x4000000
            self.assertIn(pc + 4 * delta, (cave + 0x100, cave + 0x150))
            allowed.append((at, 4))
        self.assertEqual(len(report['early_fault_guard_sites']), 4)
        for row in report['native_data_abort_filters']:
            allowed += [(original.file_at(int(row['vector'], 16), 4), 4),
                        (original.file_at(int(row['filter'], 16), 64), 64)]
        for index, (before, after) in enumerate(zip(original.data, data)):
            if before != after:
                self.assertTrue(any(start <= index < start + size for start, size in allowed), hex(index))


if __name__ == '__main__':
    unittest.main(verbosity=2)
