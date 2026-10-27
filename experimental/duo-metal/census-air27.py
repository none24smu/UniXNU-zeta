#!/usr/bin/env python3
"""Compile actual hash-validated AIR views through donor/candidate NIR and offline A660 IR3; no GPU execution."""
import argparse
import collections
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args): subprocess.run(list(map(str, args)), check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--userland', type=Path, required=True)
    p.add_argument('--host-build', type=Path, required=True)
    p.add_argument('--corpus', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); output, corpus, build = a.output.resolve(), a.corpus.resolve(), a.host_build.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source, candidate = output / 'candidate-source', output / 'candidate-host'
    run('python3', ROOT / 'prepare-air-compiler.py', '--source', a.userland.resolve() / 'tools/mesa/air', '--output', source)
    run('python3', ROOT / 'build-air-candidate-host.py', '--host-build', build, '--source', source, '--output', candidate)
    exporter = output / 'air-input-export'
    run('c++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-I', ROOT / 'include',
        ROOT / 'src/shader_container.cpp', ROOT / 'src/shader_sha256.cpp', ROOT / 'src/air_input.cpp',
        ROOT / 'air-input-export.cpp', '-lcrypto', '-o', exporter)
    manifest = json.loads((corpus / 'manifest.json').read_text())
    paths = [corpus / entry['path'] for entry in manifest['files']]
    for entry, path in zip(manifest['files'], paths):
        if sha(path) != entry['sha256']: raise ValueError('corpus source identity differs')
    exported = subprocess.run([str(exporter), str(output / 'modules'), *map(str, paths)], capture_output=True, text=True, check=False)
    if exported.returncode != 1: raise ValueError('expected only explicit GPU-archive refusal: ' + exported.stderr)
    records = [json.loads(line) for line in exported.stdout.splitlines()]
    errors = [r for r in records if r['event'] == 'error']
    if len(errors) != 1 or errors[0]['code'] != 'UnsupportedGpuArchive': raise ValueError(errors)
    rows = [r for r in records if r['event'] == 'function']
    if len(rows) != 587: raise ValueError('actual corpus function count differs')
    for row in rows:
        if sha(Path(row['module_path'])) != row['sha256']: raise ValueError('exported wrapped view hash differs')
    (output / 'exports.jsonl').write_text(exported.stdout)
    (output / 'modules.json').write_text(json.dumps(rows, indent=2) + '\n')
    stage_names = {0: 'vertex', 1: 'fragment', 2: 'kernel', 4: 'visible'}
    all_reports = {}
    for label, tools in [('baseline', build), ('candidate', candidate)]:
        air2nir = tools / ('src/compiler/air/air2nir' if label == 'baseline' else 'air2nir')
        ir3 = tools / ('src/gallium/drivers/freedreno/ir3_compiler' if label == 'baseline' else 'ir3_compiler')
        def one(row):
            try:
                result = subprocess.run([str(air2nir), '--report', row['module_path']], capture_output=True, text=True, timeout=10)
                lines = [line for line in result.stdout.splitlines() if line.startswith('module=')]
                if len(lines) != 1: return dict(row, report={'error': 'missing/ambiguous compiler report'}, returncode=result.returncode, stderr=result.stderr)
                report = dict(part.split('=', 1) for part in lines[0].split('\t') if '=' in part)
                if report.get('reader') == 'ok' and report.get('stage') != stage_names.get(row['type']):
                    raise ValueError('container TYPE / AIR stage mismatch: ' + row['name'])
                answer = dict(row, report=report, returncode=result.returncode)
                if report.get('translate') == 'ok':
                    compiled = subprocess.run([str(ir3), '--chip-id', '0x06060001', row['module_path']],
                                              capture_output=True, text=True, timeout=20)
                    answer['ir3'] = {'returncode': compiled.returncode, 'stderr': compiled.stderr[-2500:]}
                return answer
            except subprocess.TimeoutExpired:
                return dict(row, report={'error': 'compiler subprocess timed out'}, returncode=124)
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(one, rows))
        summary = {'records': len(results), 'reader': sum(r['report'].get('reader') == 'ok' for r in results),
            'nir': sum(r['report'].get('translate') == 'ok' for r in results),
            'a660_ir3': sum(r.get('ir3', {}).get('returncode') == 0 for r in results),
            'first_refusals': dict(collections.Counter(r['report'].get('error', 'ok').split(' (block ')[0] for r in results))}
        document = {'scope': 'offline default-zero function-constant corpus specialization; no GPU output',
            'tool': str(air2nir), 'tool_sha256': sha(air2nir), 'ir3_sha256': sha(ir3),
            'elapsed_seconds': time.monotonic() - started, 'summary': summary, 'rows': results}
        (output / (label + '-report.json')).write_text(json.dumps(document, indent=2) + '\n')
        all_reports[label] = document
        print(label, json.dumps(summary), flush=True)
    previous = {row['sha256']: row for row in all_reports['baseline']['rows']}
    regressions = [row['name'] for row in all_reports['candidate']['rows'] if previous[row['sha256']]['report'].get('translate') == 'ok'
                   and row['report'].get('translate') != 'ok']
    if regressions: raise ValueError('candidate NIR regressions: ' + repr(regressions))
    print('PASS: validated actual AIR views compiled, no baseline NIR regression; physical shader pixels remain separate', flush=True)


if __name__ == '__main__': main()
