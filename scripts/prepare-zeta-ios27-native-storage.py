#!/usr/bin/env python3
"""Export exact pinned NativeRamBlock with a full-stock resume-only guard.

The source driver is immutable. The exported source is selected explicitly
only for full27; it never initializes or resets a missing/mismatched store.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def export(source,expected,output,guard):
    if sha(source/'NativeRamBlock.cpp')!=expected:raise ValueError('NativeRamBlock source differs from pinned manifest')
    text=(source/'NativeRamBlock.cpp').read_text()
    old='overlay.open(ops, pages, seedHash, mode == 1, overlayBits, discardRequested())'
    if text.count(old)!=1:raise ValueError('pinned overlay-open callsite is not unique')
    output.mkdir(parents=True,exist_ok=False)
    for p in source.iterdir():
        if p.suffix in ['.cpp','.h']:shutil.copyfile(p,output/p.name)
    shutil.copyfile(guard,output/guard.name)
    text=text.replace('#include "DirectDisk.h"','#include "DirectDisk.h"\n#include "NativeIos27DataStoreGuard.h"')
    text=text.replace(old,'zetaFullStockStoreOpen(overlay, ops, pages, seedHash, mode == 1, overlayBits, discardRequested())')
    target=output/'NativeRamBlock.cpp';target.write_text(text)
    return dict(schema='zeta-ios27-resume-only-native-storage-export-v1',source=str(source.resolve()),
        source_sha256=expected,output=str(target.resolve()),output_sha256=sha(target),
        guard_header=str((output/guard.name).resolve()),guard_header_sha256=sha(output/guard.name),
        require_existing_exact_store=True,blank_stale_damaged_reset_refused_without_writes=True,
        default_26_source_changed=False,original_source_unchanged=sha(source/'NativeRamBlock.cpp')==expected,
        compiled_kernel_verified=False,phone_modified=False)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True)
    p.add_argument('--source-sha256',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--guard-header',type=Path,default=Path(__file__).resolve().parents[1]/'package/NativeIos27DataStoreGuard.h')
    a=p.parse_args();r=export(a.source,a.source_sha256,a.output,a.guard_header)
    (a.output/'native-storage-export.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))

if __name__=='__main__':main()
