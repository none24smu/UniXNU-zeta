#!/usr/bin/env python3
"""Restore bounded native Data metadata in a new host-only APFS clone."""
import argparse
import hashlib
import json
from pathlib import Path
from zeta_ios27_apfs_metadata import restore

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while b:=f.read(8<<20):h.update(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source','input','source-inventory','input-inventory','output','report']:
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-sha256',required=True);p.add_argument('--input-sha256',required=True)
    a=p.parse_args()
    for path,expected in [(a.source,a.source_sha256),(a.input,a.input_sha256)]:
        if digest(path)!=expected:raise ValueError(f'input digest mismatch: {path}')
    report=restore(a.source,a.input,a.output,json.loads(a.source_inventory.read_text()),
                   json.loads(a.input_inventory.read_text()))
    report.update(source_sha256=a.source_sha256,input_sha256=a.input_sha256,output_sha256=digest(a.output))
    a.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='compression_normalizations'},indent=2))

if __name__=='__main__':main()
