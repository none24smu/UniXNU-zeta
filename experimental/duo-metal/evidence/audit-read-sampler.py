#!/usr/bin/env python3
"""Read-only AIR intrinsic consumer audit via LLVM disassembly; no shader execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def split_arguments(text):
    parts, start, depth = [], 0, 0
    for index, char in enumerate(text):
        if char in '(<[{':
            depth += 1
        elif char in ')>]}':
            depth -= 1
        elif char == ',' and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    if text[start:].strip():
        parts.append(text[start:].strip())
    return parts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--census', type=Path, required=True)
    p.add_argument('--llvm-dis', default='llvm-dis')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    census = json.loads(a.census.read_text())
    result = dict(scope='static intrinsic call/consumer audit only; no semantic lowering or GPU proof',
                  census_sha256=hashlib.sha256(a.census.read_bytes()).hexdigest(),
                  llvm_version=subprocess.check_output([a.llvm_dis, '--version'], text=True).splitlines()[0],
                  modules=[], consumer_intrinsics={}, non_call_uses=0,
                  pointer_binding_or_sampler_zero_semantics_proven=False)
    for row in census['rows']:
        if 'air.get_read_sampler' not in row.get('report', {}).get('calls', ''):
            continue
        path = Path(row['module_path'])
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('module SHA differs from census')
        ir = subprocess.check_output([a.llvm_dis, str(path), '-o', '-'], text=True)
        module = dict(name=row['name'], source=row['source'], sha256=row['sha256'],
                      first_refusal=row['report'].get('error'), sites=[])
        current = None
        function = None
        bodies = []
        for line in ir.splitlines():
            if line.startswith('define '):
                function = line.split('@', 1)[1].split('(', 1)[0]
                current = []
            elif line == '}':
                if current is not None:
                    bodies.append((function, current))
                current = None
            elif current is not None:
                current.append(line)
        for function, lines in bodies:
            for index, line in enumerate(lines):
                matched = re.search(r'(%[^ ]+) = .*\bcall ptr addrspace\(2\) @air.get_read_sampler\(\)', line)
                if not matched:
                    continue
                value = matched.group(1)
                uses = []
                for use_index, consumer in enumerate(lines):
                    if use_index == index or not re.search(re.escape(value) + r'(?![A-Za-z0-9_.$-])', consumer):
                        continue
                    call = re.search(r'\bcall .+? @([^ (]+)\((.*)\)(?: #\d+)?(?:,.*)?$', consumer)
                    if call:
                        operands = split_arguments(call.group(2))
                        positions = [n for n, arg in enumerate(operands) if
                                     re.search(re.escape(value) + r'(?![A-Za-z0-9_.$-])', arg)]
                        uses.append(dict(callee=call.group(1), operand_positions=positions,
                                         operand_count=len(operands),
                                         trailing_operands=operands[-2:],
                                         argument_types=[re.sub(r'\s+%[^ ]+', ' <ssa>', operand)
                                                         for operand in operands]))
                        name = call.group(1)
                        result['consumer_intrinsics'][name] = result['consumer_intrinsics'].get(name, 0) + 1
                    else:
                        uses.append(dict(non_call_use_sha256=hashlib.sha256(consumer.encode()).hexdigest()))
                        result['non_call_uses'] += 1
                module['sites'].append(dict(function=function, uses=uses))
        if not module['sites']:
            raise ValueError('intrinsic advertised without parsed site: ' + row['name'])
        result['modules'].append(module)
    uses = [use for module in result['modules'] for site in module['sites'] for use in site['uses']]
    calls = [use for use in uses if 'callee' in use]
    result['consumer_count'] = len(calls)
    result['six_operands_sampler_at_one'] = all(use['operand_count'] == 6 and
                                               use['operand_positions'] == [1] for use in calls)
    result['zero_vector_fourth_operand_count'] = sum(use['argument_types'][3].endswith(' zeroinitializer')
                                                    for use in calls)
    result['dynamic_level_count'] = sum('%' in use['trailing_operands'][0] for use in calls)
    result['final_operand_counts'] = {}
    for use in calls:
        value = use['trailing_operands'][-1]
        result['final_operand_counts'][value] = result['final_operand_counts'].get(value, 0) + 1
    result['module_count'] = len(result['modules'])
    result['site_count'] = sum(len(m['sites']) for m in result['modules'])
    result['quartzcore_modules'] = sum('/QuartzCore.framework/' in m['source'] for m in result['modules'])
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k:result[k] for k in ('module_count','site_count','quartzcore_modules','consumer_intrinsics','non_call_uses')},indent=2))


if __name__ == '__main__':
    main()
