#!/usr/bin/env python3
"""Restore bounded native Data metadata in a new host-only APFS clone."""
import argparse
import hashlib
import json
import subprocess
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
    p.add_argument('--source-sha256',required=True);p.add_argument('--input-sha256',help='optional previously recorded digest of the newly copied input')
    p.add_argument('--root-name',default='data');p.add_argument('--source-prefix',default='/private/var')
    p.add_argument('--source-mount',type=Path,help='optional original RO decoder root for sealed compression headers')
    a=p.parse_args()
    if a.source_mount:
        options=subprocess.check_output(['findmnt','-n','-o','OPTIONS','--target',str(a.source_mount)],text=True).strip().split(',')
        if 'ro' not in options:raise ValueError('compression-header decoder source must be mounted read-only')
    if digest(a.source)!=a.source_sha256:raise ValueError('source image digest mismatch')
    input_digest=digest(a.input)
    if a.input_sha256 and input_digest!=a.input_sha256:raise ValueError('copied input digest mismatch')
    report=restore(a.source,a.input,a.output,json.loads(a.source_inventory.read_text()),
                   json.loads(a.input_inventory.read_text()),root_name=a.root_name,
                   source_prefix=a.source_prefix,source_mount=a.source_mount)
    report.update(source_sha256=a.source_sha256,input_sha256=input_digest,output_sha256=digest(a.output))
    a.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='compression_normalizations'},indent=2))

if __name__=='__main__':main()
