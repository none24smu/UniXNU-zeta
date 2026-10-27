#!/usr/bin/env python3
"""Materialize one complete read-only stock source into a NEW unsealed APFS.

Copies through a private Linux/APFS guest and read-only virtio9p source export.
No source filtering, guessed executable changes, source-image writes or phone
operations. Independent content/native metadata qualification is mandatory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import uuid

INIT=r'''#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
echo "ROOT-GUEST: start"
for m in netfs 9pnet 9pnet_virtio 9p; do
 insmod /modules/$m.ko || { echo "ROOT-GUEST: FAIL source module $m"; poweroff -f; }
done
insmod /apfs.ko || { echo "ROOT-GUEST: FAIL APFS module"; poweroff -f; }
mount -t 9p -o trans=virtio,version=9p2000.L,ro,msize=1048576 stock /mnt/source || { echo "ROOT-GUEST: FAIL source mount"; poweroff -f; }
mount -t apfs -o readwrite /dev/vda /mnt/apfs || { echo "ROOT-GUEST: FAIL target mount"; dmesg | tail -30; poweroff -f; }
/bin/stock-tree-copy /mnt/source /mnt/apfs
result=$?
echo "ROOT-GUEST: copy-result $result"
sync
umount /mnt/apfs && echo "ROOT-GUEST: target-unmounted" || echo "ROOT-GUEST: FAIL target umount"
umount /mnt/source
dmesg | grep -i -E 'apfs|error' | tail -30
echo "ROOT-GUEST: done"
poweroff -f
'''

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while b:=f.read(8<<20):h.update(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-root','source-inventory','kernel','module','busybox','copy-tool','mkapfs','output-directory']:
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--root-name',required=True);p.add_argument('--label',required=True)
    p.add_argument('--size-mib',type=int,required=True);p.add_argument('--memory-mib',type=int,default=4096)
    a=p.parse_args();options=subprocess.check_output(['findmnt','-n','-o','OPTIONS','--target',str(a.source_root)],text=True).strip().split(',')
    if 'ro' not in options:raise ValueError('source must already be mounted read-only')
    source=json.loads(a.source_inventory.read_text())['roots'][a.root_name]
    if source['errors'] or not source.get('hash_files'):raise ValueError('require complete fully hashed original source inventory')
    expected={k:sum(e['kind']==k for e in source['entries'].values()) for k in ['file','directory','symlink']}
    expected_bytes=sum(e['size'] for e in source['entries'].values() if e['kind']=='file')
    minimum=expected_bytes+max(64<<20,len(source['entries'])*4096)+(64<<20)
    if a.size_mib*(1<<20)<minimum:raise ValueError('capacity cannot preserve full source; no entries will be dropped')
    if a.output_directory.exists():raise ValueError('refuse existing output directory')
    a.output_directory.mkdir(parents=True);root=a.output_directory/'initramfs'
    for name in ['bin','modules','dev','proc','sys','mnt/source','mnt/apfs']:(root/name).mkdir(parents=True,exist_ok=True)
    shutil.copyfile(a.busybox,root/'bin/busybox');(root/'bin/busybox').chmod(0o755)
    shutil.copyfile(a.copy_tool,root/'bin/stock-tree-copy');(root/'bin/stock-tree-copy').chmod(0o755)
    shutil.copyfile(a.module,root/'apfs.ko')
    version=subprocess.check_output(['modinfo','-F','vermagic',str(a.module)],text=True).split()[0]
    modules=Path('/lib/modules')/version/'kernel'
    for name,relative in [('netfs','fs/netfs/netfs.ko.zst'),('9pnet','net/9p/9pnet.ko.zst'),('9pnet_virtio','net/9p/9pnet_virtio.ko.zst'),('9p','fs/9p/9p.ko.zst')]:
        with (root/f'modules/{name}.ko').open('wb') as out:subprocess.run(['zstd','-d','-c',str(modules/relative)],stdout=out,check=True)
    (root/'init').write_text(INIT);(root/'init').chmod(0o755)
    listing=subprocess.check_output(['find','.'],cwd=root)
    with (a.output_directory/'initramfs.cpio').open('wb') as out:subprocess.run(['cpio','-o','-H','newc'],cwd=root,input=listing,stdout=out,stderr=subprocess.PIPE,check=True)
    identity=str(uuid.uuid4()).upper();image=a.output_directory/'unsealed.apfs'
    with image.open('xb') as f:f.truncate(a.size_mib<<20)
    subprocess.run([str(a.mkapfs),'-L',a.label,'-s','-u',identity,str(image)],check=True)
    report=dict(schema='zeta-ios27-complete-unsealed-root-copy-v1',source_root=str(a.source_root.resolve()),source_inventory=str(a.source_inventory.resolve()),
        root_name=a.root_name,expected_counts=expected,expected_file_bytes=expected_bytes,capacity_minimum_bytes=minimum,
        logical_bytes=a.size_mib<<20,provisional_volume_uuid=identity,image=str(image.resolve()),
        kernel_sha256=digest(a.kernel),apfs_module_sha256=digest(a.module),copy_tool_sha256=digest(a.copy_tool),
        initramfs_sha256=digest(a.output_directory/'initramfs.cpio'),source_export_readonly=True,stock_entries_filtered=False,
        source_and_original_images_unchanged=True,executable_conversion_performed=False,
        independent_content_readback_passed=False,native_metadata_normalization_pending=True,profile_published=False,phone_modified=False)
    (a.output_directory/'copy-plan.json').write_text(json.dumps(report,indent=2)+'\n')
    command=['qemu-system-x86_64','-enable-kvm','-cpu','host','-m',str(a.memory_mib),'-smp','2','-kernel',str(a.kernel),
        '-initrd',str(a.output_directory/'initramfs.cpio'),'-append','console=ttyS0 quiet panic=-1','-nographic','-no-reboot',
        '-drive',f'file={image},format=raw,if=virtio',
        '-virtfs',f'local,path={a.source_root.resolve()},mount_tag=stock,security_model=none,readonly=on']
    (a.output_directory/'qemu-command.json').write_text(json.dumps(command,indent=2)+'\n')
    log=a.output_directory/'guest.log'
    with log.open('w') as out:result=subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,timeout=14400)
    console=log.read_text(errors='replace');m=re.search(r'COPY-COMPLETE files=(\d+) directories=(\d+) symlinks=(\d+) hardlinks=(\d+) file_bytes=(\d+)',console)
    failures=[line for line in console.splitlines() if 'COPY-FAIL' in line or 'ROOT-GUEST: FAIL' in line]
    if not m:failures.append('missing complete-copy marker')
    else:
        actual=dict(zip(['file','directory','symlink','hardlinks','file_bytes'],map(int,m.groups())))
        if any(actual[k]!=expected[k] for k in expected) or actual['file_bytes']!=expected_bytes:failures.append('complete source counts/bytes differ')
        report['actual_counts']=actual
    for marker in ['ROOT-GUEST: copy-result 0','ROOT-GUEST: target-unmounted','ROOT-GUEST: done']:
        if marker not in console:failures.append('missing '+marker)
    report.update(guest_returncode=result.returncode,failures=failures,guest_copy_completed=not failures)
    (a.output_directory/'copy-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if failures:raise SystemExit(3)

if __name__=='__main__':main()
