"""Adversarial retained-capture checks. Opt into exact local native artifacts."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('normalizer', SCRIPTS / 'normalize-zeta-native-cpu.py')
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)
SOURCE = os.environ.get('ZETA_NATIVE_CPU_EVIDENCE')


@unittest.skipUnless(SOURCE, 'set ZETA_NATIVE_CPU_EVIDENCE to retained native experiment directory')
class NativeEvidenceTests(unittest.TestCase):
    def copy(self, destination):
        source = Path(SOURCE).resolve()
        for relative in ['candidate-kernel.macho', 'native-cpu-result2.json',
                'isa-artifact-v3/build.json', 'isa-artifact-v3/zeta-isa-probe',
                'isa-artifact-v3/zeta-isa-launcher', 'isa-artifact-v3/fixtures/cases.json',
                *[f'native-cpu2-{i}-{name}.log' for i,name in enumerate(
                    ['off','probe-enabled','platform-name-denied','platform-enabled','off-again'])],
                *[str(x.relative_to(source)) for x in (source / 'corroborating-readback').iterdir() if x.is_file()]]:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(source / relative)

    def write(self, path, data):
        path.unlink()
        path.write_text(data)

    def test_real_complete_capture(self):
        value = normalizer.normalize(SOURCE)
        self.assertTrue(value['native_cssc_platform_scope_passed'])
        self.assertFalse(value['conversion_qualified'])

    def test_changed_summary_or_raw_capture_rejected(self):
        for change in ['summary', 'raw', 'kernel', 'missing-control', 'alias']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp); self.copy(directory)
                path = directory / 'native-cpu-result2.json'
                value = json.loads(path.read_text())
                if change == 'summary': value['phases'][1]['counter_delta'][1] -= 1
                if change == 'kernel': value['kernel_sha256'] = '0'*64
                if change == 'missing-control': value['phases'].pop(2)
                self.write(path, json.dumps(value))
                if change == 'raw':
                    path = directory / 'native-cpu2-1-probe-enabled.log'
                    self.write(path, path.read_text().replace('"passed":9', '"passed":8', 1))
                if change == 'alias':
                    self.write(directory / 'corroborating-readback/zeta-isa-test', 'changed')
                with self.assertRaises(ValueError): normalizer.normalize(directory)

    def test_consistently_forged_nonplatform_or_missing_cases_rejected(self):
        for change in ['platform', 'cssc', 'capability']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp); self.copy(directory)
                path = directory / 'native-cpu-result2.json'
                value = json.loads(path.read_text())
                rows = value['phases'][3]['records']
                if change == 'platform':
                    next(x for x in rows if x['kind'] == 'code-signing')['platform_binary'] = False
                elif change == 'cssc':
                    rows.remove(next(x for x in rows if x['kind'] == 'cssc'))
                else:
                    rows.remove(next(x for x in rows if x['kind'] == 'capability'))
                self.write(path, json.dumps(value))
                log = directory / 'native-cpu2-3-platform-enabled.log'
                text = log.read_text().splitlines(); remaining = iter(rows)
                text = [json.dumps(next(remaining)) if x.startswith('{') else x for x in text
                    if not (change in ('cssc','capability') and x.startswith('{') and
                    json.loads(x).get('kind') == change and json.loads(x).get('name') in ('zeta_smax32_r0','baseline-add'))]
                self.write(log, '\n'.join(text)+'\n')
                with self.assertRaises(ValueError): normalizer.normalize(directory)


if __name__ == '__main__': unittest.main()
