#!/usr/bin/env python3
"""Restore native APFS hardlink groups hidden by FUSE nlink observations.

Only an explicitly completed, unqualified host reconstruction is writable.
The original source image is read-only; no phone/device paths are accepted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import zeta_apfs_image as apfs
from zeta_ios27_apfs_metadata import Catalog,native_hardlink_groups

INIT=r'''#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
insmod /apfs.ko || { echo "LINK-GUEST: FAIL module"; poweroff -f; }
mount -t apfs -o readwrite /dev/vda /mnt/apfs || { echo "LINK-GUEST: FAIL mount"; poweroff -f; }
/bin/stock-tree-copy --repair-hardlinks /hardlinks.bin /mnt/apfs
echo "LINK-GUEST: result $?"
sync
umount /mnt/apfs && echo "LINK-GUEST: unmounted" || echo "LINK-GUEST: FAIL umount"
echo "LINK-GUEST: done"
poweroff -f
'''

def plan_bytes(groups):
    pairs=[(group[0].lstrip('/'),p.lstrip('/')) for group in groups for p in group[1:]]
    out=bytearray(struct.pack('<8sQ',b'ZHLINK01',len(pairs)))
    for pair in pairs:
        for path in pair:
            b=path.encode();out+=struct.pack('<I',len(b))+b
    return bytes(out)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-image','copy-directory','copy-tool','kernel','module','busybox']:
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-prefix',default='/');p.add_argument('--root-name',required=True)
    a=p.parse_args();copy=json.loads((a.copy_directory/'copy-result.json').read_text());image=Path(copy['image'])
    if (copy.get('root_name')!=a.root_name or not copy.get('guest_copy_completed') or
            image.resolve().parent!=a.copy_directory.resolve() or image.resolve()==a.source_image.resolve() or not image.is_file()):
        raise ValueError('require owned completed unqualified reconstruction, never an original/control image')
    mounted=subprocess.run(['findmnt','-rn','-S',str(image.resolve())],capture_output=True,text=True)
    if mounted.returncode==0:raise ValueError('unmount task-owned read-only target inspection before guest writes')
    with a.source_image.open('rb') as f:
        c=apfs.Container(f);v,=c.volumes();cat=Catalog(v);groups=native_hardlink_groups(cat,cat.paths(a.source_prefix))
        data_groups=native_hardlink_groups(cat,cat.paths('/private/var')) if a.root_name=='main' else None
    work=a.copy_directory/'hardlink-repair';work.mkdir(exist_ok=False)
    root=work/'initramfs'
    for name in ['bin','dev','proc','sys','mnt/apfs']:(root/name).mkdir(parents=True,exist_ok=True)
    shutil.copyfile(a.busybox,root/'bin/busybox');(root/'bin/busybox').chmod(0o755)
    shutil.copyfile(a.copy_tool,root/'bin/stock-tree-copy');(root/'bin/stock-tree-copy').chmod(0o755)
    shutil.copyfile(a.module,root/'apfs.ko');(root/'hardlinks.bin').write_bytes(plan_bytes(groups))
    (root/'init').write_text(INIT);(root/'init').chmod(0o755)
    listing=subprocess.check_output(['find','.'],cwd=root)
    with (work/'initramfs.cpio').open('wb') as out:subprocess.run(['cpio','-o','-H','newc'],cwd=root,input=listing,stdout=out,stderr=subprocess.PIPE,check=True)
    report=dict(schema='zeta-ios27-native-hardlink-repair-v1',source_image=str(a.source_image.resolve()),source_prefix=a.source_prefix,
        root_name=a.root_name,groups=groups,group_count=len(groups),aliases=sum(len(x)-1 for x in groups),
        original_source_unchanged=True,executable_bytes_edited=False,phone_modified=False)
    (work/'native-source-hardlinks.json').write_text(json.dumps(report,indent=2)+'\n')
    if data_groups is not None:
        (work/'source-data-native-hardlinks.json').write_text(json.dumps(dict(groups=data_groups,
            group_count=len(data_groups),aliases=sum(len(x)-1 for x in data_groups),source_image=str(a.source_image.resolve()),source_prefix='/private/var'),indent=2)+'\n')
    command=['qemu-system-x86_64','-enable-kvm','-cpu','host','-m','2048','-smp','2','-kernel',str(a.kernel),
        '-initrd',str(work/'initramfs.cpio'),'-append','console=ttyS0 quiet panic=-1','-nographic','-no-reboot',
        '-drive',f'file={image},format=raw,if=virtio']
    with (work/'guest.log').open('w') as log:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=3600)
    text=(work/'guest.log').read_text(errors='replace')
    for marker in [f'HARDLINK-COMPLETE aliases={report["aliases"]}','LINK-GUEST: result 0','LINK-GUEST: unmounted','LINK-GUEST: done']:
        if marker not in text or 'FAIL' in text:raise ValueError('hardlink guest failed; see retained log')
    with image.open('rb') as f:
        c=apfs.Container(f);v,=c.volumes();cat=Catalog(v);actual=native_hardlink_groups(cat,cat.paths())
    if groups!=actual:raise ValueError('native target inode equivalence differs after repair')
    report['native_inode_group_readback_passed']=True
    (work/'repair-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='groups'},indent=2))

if __name__=='__main__':main()
