#!/usr/bin/env python3
"""Verify retained five-mode CPU captures offline; never qualify conversion.

Input is the native experiment directory. Original phase logs remain distinct
from later corroborating kernel/executable readback. No phone is accessed.
"""
import argparse
import hashlib
import json
from pathlib import Path


def require(value, message):
    if not value:
        raise ValueError(message)


def record(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def unique(rows, kind):
    found = [x for x in rows if x.get('kind') == kind]
    require(len(found) == 1, 'missing/duplicate ' + kind)
    return found[0]


def normalize(directory):
    directory = Path(directory).resolve()
    raw_result = directory / 'native-cpu-result2.json'
    result = json.loads(raw_result.read_text())
    kernel = record(directory / 'candidate-kernel.macho')
    require(kernel['sha256'] == result['kernel_sha256'], 'kernel mismatch')
    require(result.get('passed') is True and result.get('final_mode_restore', {}).get('after') == 0,
            'experiment failed or compatibility mode not restored')
    artifact = directory / 'isa-artifact-v3'
    build = json.loads((artifact / 'build.json').read_text())
    fixtures = json.loads((artifact / 'fixtures/cases.json').read_text())
    require(len(fixtures) == 32 and len({x['name'] for x in fixtures}) == 32, 'fixture coverage')
    probe = record(artifact / 'zeta-isa-probe')
    from zeta_x1_compat import probe_cdhash
    cdhash = probe_cdhash((artifact / 'zeta-isa-probe').read_bytes())
    require(cdhash == build['files']['zeta-isa-probe']['cdhash'], 'CodeDirectory mismatch')
    for name, expected in build['files'].items():
        actual = record(artifact / name)
        require(actual['sha256'] == expected['sha256'] and actual['bytes'] == expected['bytes'], 'artifact mismatch ' + name)
        require(result['executables'][name] == {'sha256': actual['sha256'], 'readback_bytes': actual['bytes']}, 'original executable readback mismatch')
    phases = [('off', 0, 'i', False), ('probe-enabled', 1, 'i', True),
              ('platform-name-denied', 1, 'p', False), ('platform-enabled', 2, 'p', True),
              ('off-again', 0, 'i', False)]
    require(len(result['phases']) == len(phases), 'phase count')
    observations = []
    for index, (name, mode, selection, enabled) in enumerate(phases):
        phase = result['phases'][index]
        require((phase['name'], phase['requested_mode'], phase['selector']) == (name, mode, selection), 'phase identity')
        require(phase['gate_consumed'] is True and phase['write']['after'] == mode, 'gate/mode failure')
        path = directory / f'native-cpu2-{index}-{name}.log'
        text = path.read_text()
        rows = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
        require(rows == phase['records'], 'raw phase/summary discrepancy ' + name)
        require(f'zeta-isa-launcher: selection {selection}' in text and 'zeta-isa-launcher: child status 0' in text, 'launcher completion')
        require(unique(rows, 'complete') == {'kind': 'complete', 'cssc_cases': 32,
                'passed': 32 if enabled else 0, 'trapped': 0 if enabled else 32, 'failures': 0}, 'CSSC summary')
        cssc = [x for x in rows if x.get('kind') == 'cssc']
        require(len(cssc) == 32, 'CSSC record count')
        for actual, fixture in zip(cssc, fixtures):
            require(actual == {'kind': 'cssc', 'name': fixture['name'], 'instruction': f"0x{fixture['instruction']:08x}",
                    'signal': 0 if enabled else 4, 'passed': 9 if enabled else 0, 'failed': 0}, 'CSSC instruction/edge discrepancy')
        counters = [b-a for a,b in zip(phase['before'], phase['after'])]
        require(len(counters) == 8 and counters == phase['counter_delta'] and counters[1] == (10288 if enabled else 0), 'emulation counters')
        flags = unique(rows, 'code-signing'); identity = unique(rows, 'code-directory')
        require(flags['status'] == 0 and flags['platform_binary'] is True and int(flags['flags'],16) & 0x04000000,
                'actual platform status absent')
        require(identity['status'] == 0 and identity['cdhash'] == cdhash, 'actual platform CDHash absent')
        capabilities = [x for x in rows if x.get('kind') == 'capability']
        require(len({x['name'] for x in capabilities}) == len(capabilities), 'duplicate capability')
        caps = {x['name']: x for x in capabilities}
        require(set(caps) == {'baseline-add', 'addpt', 'maddpt', 'ldapur', 'mte-irg', 'sha512h-zero',
            'fjcvtzs-zero', 'fjcvtzs-positive-fraction', 'fjcvtzs-negative-fraction', 'fjcvtzs-modulo32',
            'fjcvtzs-qnan', 'fjcvtzs-infinity', 'pauth-pacia-autia', 'pauth-lr-paired-leaf', 'unallocated'}, 'capability coverage')
        require(caps['baseline-add']['signal'] == 0 and caps['baseline-add']['semantic_pass'] is True, 'baseline positive control')
        require(all(x['signal'] == 4 for name,x in caps.items() if name != 'baseline-add'), 'unsupported instruction unexpectedly available')
        observations.append({'name': name, 'kernel_sha256': kernel['sha256'], 'kernel_mode': mode,
            'basename': 'zeta-isa-test' if selection == 'p' else 'zeta-isa-probe',
            'csops_status_result': flags['status'], 'csops_status': int(flags['flags'],16),
            'csops_cdhash_result': identity['status'], 'csops_cdhash': cdhash,
            'cssc': 'pass' if enabled else 'sigill', 'emulated': counters[1], 'capture': record(path)})
    corroboration_path = directory / 'corroborating-readback/result.json'
    corroboration = json.loads(corroboration_path.read_text())
    require(corroboration['kernel_sha256'] == kernel['sha256'] and corroboration['compatibility_mode'] == 0, 'later corroboration kernel/mode')
    for symbol, window in corroboration['windows'].items():
        actual = record(corroboration_path.parent / window['file'])
        original = result['kernel_runtime'][symbol]
        require(actual['bytes'] == window['bytes'] == original['matched_bytes'] == 128 and
                actual['sha256'] == window['sha256'] == original['sha256'] and window['va'] == original['va'], 'corroborating code window mismatch')
    for name, item in corroboration['files'].items():
        actual = record(corroboration_path.parent / name)
        expected = build['files']['zeta-isa-probe' if name == 'zeta-isa-test' else name]
        require(actual['sha256'] == item['sha256'] == expected['sha256'] and actual['bytes'] == item['bytes'] == expected['bytes'], 'later executable readback mismatch')
    native_rows = result['phases'][0]['records']
    return {'schema': 'zeta-x1-native-cpu-checkpoint-v1', 'normalizer': record(__file__), 'kernel': kernel,
        'raw_result': record(raw_result), 'probe': probe, 'cdhash': cdhash,
        'artifact_build': record(artifact / 'build.json'), 'fixtures': record(artifact / 'fixtures/cases.json'),
        'observations': observations, 'later_corroboration': record(corroboration_path),
        'later_corroboration_scope': corroboration['evidence_scope'],
        'guest_observations': [x for x in native_rows if x['kind'] in ('sysctl','capability','commpage-capabilities64','commpage-tpro')],
        'native_cssc_platform_scope_passed': True, 'conversion_qualified': False,
        'pending': ['Native GCS control-state qualification; ENOENT is not absence proof',
            'Whole-input retained-feature and code-boundary qualification',
            'Effective ordinary-pointer/CPTA-OFF ABI qualification',
            'Loader, new kernel API and actual iOS27 process execution'],
        'limits': ['Later corroboration bytes were captured after the original phases, not during them',
            'Fault-fetch/no-mutation/PC behavior has separate host adapter evidence; this capture does not replace it',
            'Instruction trap timings include wrapper/load and are not controlled frame-rate measurements']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output)
    require(not output.exists(), 'preserve prior normalization output')
    output.write_text(json.dumps(normalize(args.directory), indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    main()
