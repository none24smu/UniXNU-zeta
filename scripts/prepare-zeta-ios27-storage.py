#!/usr/bin/env python3
"""Host-only complete iOS27 storage preparation; never opens a device.

Use a bounded metadata-only loader seed plus the existing SHNGDATA direct
store, rather than increasing bootloader RAM-input limits for stock apps.
Original decoded files remain on persistent storage. Root windows stay RO.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import struct
import subprocess
import sys
import uuid
import zlib

from zeta_ios27_apfs_metadata import Catalog
import zeta_apfs_image as apfs

PAGE=4096
MIB=1<<20

def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        while chunk:=f.read(8*MIB):h.update(chunk)
    return h.hexdigest()

def merge_ranges(ranges):
    result=[]
    for first,end in sorted(ranges):
        if first<0 or end<=first or (first|end)%PAGE:raise ValueError('unaligned/empty extent')
        if result and first<=result[-1][1]:result[-1]=(result[-1][0],max(end,result[-1][1]))
        else:result.append((first,end))
    return result

def sparse_copy(source,output,output_offset=0,omit=()):
    """Copy actual nonzero pages; omitted ranges are deliberate file data only."""
    excluded=merge_ranges(omit);index=0;copied=0
    with Path(source).open('rb') as src:
        for base in range(0,Path(source).stat().st_size,8*MIB):
            chunk=src.read(8*MIB)
            for i in range(0,len(chunk),PAGE):
                at=base+i
                while index<len(excluded) and excluded[index][1]<=at:index+=1
                if index<len(excluded) and excluded[index][0]<=at<excluded[index][1]:continue
                page=chunk[i:i+PAGE]
                if page!=bytes(len(page)):
                    output.seek(output_offset+at);output.write(page);copied+=len(page)
    return copied

def overlay_header(pages,identity,generation=1):
    b=bytearray(PAGE)
    struct.pack_into('<8sIIQ32sI',b,0,b'SHNGDATA',1,64,pages,bytes.fromhex(identity),generation)
    struct.pack_into('<I',b,60,zlib.crc32(b[:60]));return bytes(b)

def overlay_geometry(partition_bytes,root_image_bytes,logical_bytes,reserve_mib=1024):
    if not isinstance(reserve_mib,int) or not 1024<=reserve_mib<=16384:
        raise ValueError('explicit Data reserve must be1024..16384MiB, matching the native parser')
    if (partition_bytes|logical_bytes|root_image_bytes)%PAGE:raise ValueError('unaligned storage geometry')
    pages=logical_bytes//PAGE;bitmap=(pages+32767)//32768
    window=(1+bitmap+pages)*PAGE;offset=partition_bytes-reserve_mib*MIB-window
    if offset<root_image_bytes+4*MIB or window>partition_bytes//4:
        raise ValueError('Data store overlaps root/guard or exceeds quarter-partition bound')
    return dict(partition_bytes=partition_bytes,root_image_bytes=root_image_bytes,
        logical_bytes=logical_bytes,pages=pages,bitmap_blocks=bitmap,store_bytes=window,
        store_partition_offset=offset,reserve_mib=reserve_mib,root_guard_bytes=4*MIB,
        data_offset_in_store=(1+bitmap)*PAGE,tail_reserved_bytes=reserve_mib*MIB)

def data(args):
    if sha(args.input)!=args.input_sha256:raise ValueError('full Data input SHA mismatch')
    args.output.mkdir(parents=True,exist_ok=False)
    logical=args.input.stat().st_size
    if logical<=2<<30:raise ValueError('this route requires existing large direct-disk branch')
    ranges=[]
    with args.input.open('rb') as f:
        c=apfs.Container(f);v,=c.volumes();cat=Catalog(v)
        for oid,(value,_,_) in cat.inodes.items():
            if not stat.S_ISREG(struct.unpack_from('<H',value,80)[0]):continue
            stream=struct.unpack_from('<Q',value,8)[0]
            for _,length,physical in cat.extents.get(stream,[]):
                if not physical or physical*PAGE+length>logical:raise ValueError('file data extent bounds')
                if any(physical<=node<physical+length//PAGE for node in cat.nodes):
                    raise ValueError('file payload overlaps native filesystem metadata')
                ranges.append((physical*PAGE,physical*PAGE+length))
        volume_uuid=str(uuid.UUID(bytes=v.superblock[0xf0:0x100])).upper()
        retained_nodes=sorted(cat.nodes)
    ranges=merge_ranges(ranges)
    anchor=args.output/'Data-metadata-anchor.apfs'
    with anchor.open('xb') as out:
        out.truncate(logical);retained=sparse_copy(args.input,out,omit=ranges)
    packed=load_module('packed_ramdisk',args.unixnu/'drivers/DarwinBoot/Test/packed_ramdisk.py')
    boot=args.output/'Data-metadata-anchor.dbr';metadata=packed.pack(anchor,boot)
    if metadata['encoded_bytes']>256*MIB:raise ValueError('anchor exceeds unchanged loader bound')
    pages=logical//PAGE;bitmap_blocks=(pages+32767)//32768
    bitmap=bytearray(bitmap_blocks*PAGE)
    for i in range(pages//8):bitmap[i]=255
    if pages%8:bitmap[pages//8]=(1<<(pages%8))-1
    store=args.output/'Data-direct-store.img';start=(1+bitmap_blocks)*PAGE
    with store.open('xb') as out:
        out.truncate(start+logical)
        out.write(overlay_header(pages,metadata['sha256']));out.write(bitmap)
        sparse_copy(args.input,out,output_offset=start)
    # Independent full page-payload readback; every page is present, including
    # zeros. It cannot accidentally expose old bytes beyond the source file.
    h=hashlib.sha256()
    with store.open('rb') as f:
        head=f.read(PAGE);bits=f.read(bitmap_blocks*PAGE)
        if head!=overlay_header(pages,metadata['sha256']) or bits!=bitmap:raise ValueError('store metadata readback')
        while chunk:=f.read(8*MIB):h.update(chunk)
    if h.hexdigest()!=args.input_sha256:raise ValueError('full store decoded-data readback failed')
    # APFS metadata bytes are exact before store attachment. Directory/volume
    # discovery therefore does not depend on an early file-content read.
    with anchor.open('rb') as f:
        ac=apfs.Container(f);av,=ac.volumes();a=Catalog(av)
        if len(a.inodes)!=len(cat.inodes) or len(a.children)!=len(cat.children):raise ValueError('anchor metadata disappeared')
        if a.nodes!=set(retained_nodes):raise ValueError('anchor native node layout changed')
    report=dict(schema='zeta-ios27-full-data-direct-store-v1',input=str(args.input.resolve()),
        input_sha256=args.input_sha256,logical_bytes=logical,volume_uuid=volume_uuid,
        anchor=str(anchor.resolve()),anchor_dbr=str(boot.resolve()),anchor_dbr_sha256=sha(boot),
        anchor_encoded_bytes=metadata['encoded_bytes'],anchor_nonzero_bytes=retained,
        seed_identity=metadata['sha256'],omitted_file_data_ranges=[dict(offset=a,bytes=b-a) for a,b in ranges],
        omitted_file_data_bytes=sum(b-a for a,b in ranges),store=str(store.resolve()),store_bytes=store.stat().st_size,
        store_sha256=sha(store),store_payload_sha256=h.hexdigest(),all_pages_present=True,
        bitmap_blocks=bitmap_blocks,data_offset_in_store=start,
        anchor_apfs_metadata_readback_passed=True,store_full_data_readback_passed=True,
        loader_limit_changed=False,required_bootargs=['sheng-data-persist=2','sheng-log-reserve=1024'],
        forbidden_bootargs=['sheng-data-reset','sheng-lite','sheng-disable-jobs'],
        pre_attach_hardware_uuid_discovery_verified=False,phone_modified=False,boot_qualified=False)
    (args.output/'data-storage.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='omitted_file_data_ranges'},indent=2))

def roots(args):
    """All three original APFS namespaces, immutable; sign only host artifacts."""
    wrap=load_module('zeta_root_wrap',Path(__file__).with_name('build-zeta-root.py'))
    signing=load_module('owner_manifest',args.unixnu/'kits/VerifiedRoot/tools/manifest.py')
    anchor=signing.public_anchor(args.public_key)
    expected_header=''.join(f'0x{b:02x}' for b in anchor)
    # The generated header must match the existing board trust anchor. Do not
    # replace a trusted key or silently create a new incompatible signer.
    import re
    observed=''.join(re.findall(r'0x[0-9a-fA-F]{2}',args.public_header.read_text())).lower()
    if observed!=expected_header:raise ValueError('owner key differs from selected board public anchor')
    args.output.mkdir(parents=True,exist_ok=False);windows=[]
    for name,source in [('OS',args.os),('SystemOS',args.systemos),('AppOS',args.appos)]:
        with source.open('rb') as f:
            c=apfs.Container(f);v,=c.volumes();identity=uuid.UUID(bytes=v.superblock[0xf0:0x100])
        item=wrap.wrap_apfs(source,args.output/(name+'.img'),name,identity)
        with Path(item['path']).open('rb') as f:
            policy=signing.make(f,item['size'],args.private_key,args.public_key,identity,1,args.output/(name+'-policy'))
        if policy['image_sha256']!=item['sha256']:raise ValueError('policy/input identity mismatch')
        item.update(policy_path=str((args.output/(name+'-policy/manifest.bin')).resolve()),
                    policy_bytes=(args.output/(name+'-policy/manifest.bin')).stat().st_size)
        windows.append(item)
    cursor=MIB
    for w in windows:w['offset']=cursor;cursor+=wrap.align(w['size'])
    for w in windows:w['policy_offset']=cursor;cursor+=wrap.align(w['policy_bytes'])
    facts=json.loads(args.userdata_facts.read_text());capacity=facts['userdata_bytes']
    if cursor>capacity:raise ValueError('complete roots exceed recorded userdata capacity')
    manifest=bytearray(PAGE);manifest[:8]=b'SHNGROOT';struct.pack_into('<IIQ',manifest,8,1,len(windows),cursor)
    for i,w in enumerate(windows):
        extra=struct.pack('<QQ24s',w['policy_offset'],w['policy_bytes'],bytes(24))
        struct.pack_into('<32sQQII32s40s',manifest,24+128*i,w['name'].encode(),w['offset'],w['size'],512,1,bytes.fromhex(w['sha256']),extra)
    manifest[4064:]=hashlib.sha256(manifest[:4064]).digest()
    image=args.output/'userdata-root-prefix.img'
    with image.open('xb') as out:
        out.truncate(cursor);out.write(manifest)
        for w in windows:
            for path,offset in [(w['path'],w['offset']),(w['policy_path'],w['policy_offset'])]:
                sparse_copy(Path(path),out,offset)
    report=dict(schema='zeta-ios27-complete-owner-root-storage-v1',image=str(image.resolve()),
        image_bytes=cursor,image_sha256=sha(image),windows=windows,userdata_bytes=capacity,
        userdata_facts_source=str(args.userdata_facts.resolve()),
        trusted_key_sha256=hashlib.sha256(anchor).hexdigest(),all_three_namespaces_preserved=True,
        isa_converted=False,metadata_images_unchanged=True,phone_modified=False,boot_qualified=False,
        mount_requirements={'OS':'/','SystemOS':'/System/Cryptexes/OS','AppOS':'/System/Cryptexes/App'})
    profile=args.output/'NativeIos27StorageProfile.h'
    profile.write_text('/* Generated from actual retained APFS volume UUIDs. */\n#pragma once\n'+''.join(
        f'#define ZETA_IOS27_{w["name"].upper()}_VOLUME_UUID "{w["volume_uuid"]}"\n' for w in windows))
    report['mount_profile_header']=str(profile.resolve())
    (args.output/'root-storage.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='windows'},indent=2))


def preboot(args):
    """Add a tiny mountpoint scaffold without altering any original OS image."""
    old=json.loads(args.roots.read_text())
    if len(old['windows'])!=3:raise ValueError('require exactly three preserved stock source windows')
    wrap=load_module('zeta_root_wrap',Path(__file__).with_name('build-zeta-root.py'))
    signing=load_module('owner_manifest',args.unixnu/'kits/VerifiedRoot/tools/manifest.py')
    anchor=signing.public_anchor(args.public_key)
    if hashlib.sha256(anchor).hexdigest()!=old['trusted_key_sha256']:raise ValueError('Preboot signer differs from original root anchor')
    args.output.mkdir(parents=True,exist_ok=False)
    with args.preboot.open('rb') as f:
        c=apfs.Container(f);v,=c.volumes();identity=uuid.UUID(bytes=v.superblock[0xf0:0x100]);cat=Catalog(v)
        if set(cat.paths())!={'/','/Cryptexes','/Cryptexes/OS','/Cryptexes/App'}:
            raise ValueError('Preboot scaffold must contain only exact empty stock mountpoints')
    item=wrap.wrap_apfs(args.preboot,args.output/'Preboot.img','Preboot',identity)
    with Path(item['path']).open('rb') as f:
        signing.make(f,item['size'],args.private_key,args.public_key,identity,1,args.output/'Preboot-policy')
    item.update(policy_path=str((args.output/'Preboot-policy/manifest.bin').resolve()),
                policy_bytes=(args.output/'Preboot-policy/manifest.bin').stat().st_size,
                offset=old['image_bytes'])
    item['policy_offset']=wrap.align(item['offset']+item['size'])
    end=wrap.align(item['policy_offset']+item['policy_bytes'])
    windows=old['windows']+[item];manifest=bytearray(PAGE);manifest[:8]=b'SHNGROOT'
    struct.pack_into('<IIQ',manifest,8,1,4,end)
    for i,w in enumerate(windows):
        extra=struct.pack('<QQ24s',w['policy_offset'],w['policy_bytes'],bytes(24))
        struct.pack_into('<32sQQII32s40s',manifest,24+128*i,w['name'].encode(),w['offset'],w['size'],512,1,bytes.fromhex(w['sha256']),extra)
    manifest[4064:]=hashlib.sha256(manifest[:4064]).digest()
    image=args.output/'userdata-root-prefix.img'
    subprocess.run(['cp','--reflink=auto','--sparse=always','--',old['image'],str(image)],check=True)
    with image.open('r+b') as f:
        f.truncate(end);f.write(manifest)
        for p,at in [(item['path'],item['offset']),(item['policy_path'],item['policy_offset'])]:
            f.seek(at)
            with Path(p).open('rb') as src:
                while b:=src.read(8*MIB):f.write(b)
    # One independent readback pass qualifies every copied original window,
    # appended scaffold and signature envelope, and the new complete prefix.
    boundaries={0,end}
    regions=[]
    for w in windows:
        for key,at,length,expected in [('window',w['offset'],w['size'],w['sha256']),
                ('policy',w['policy_offset'],w['policy_bytes'],sha(w['policy_path']))]:
            boundaries.update([at,at+length]);regions.append((w['name'],key,at,at+length,expected,hashlib.sha256()))
    total=hashlib.sha256();points=sorted(boundaries)
    with image.open('rb') as f:
        for left,right in zip(points,points[1:]):
            active=[r for r in regions if r[2]<=left and right<=r[3]];remaining=right-left
            while remaining:
                b=f.read(min(8*MIB,remaining))
                if not b:raise ValueError('assembled root prefix truncated')
                total.update(b)
                for r in active:r[5].update(b)
                remaining-=len(b)
    checks=[]
    for name,kind,_,_,expected,h in regions:
        if h.hexdigest()!=expected:raise ValueError('assembled '+name+' '+kind+' readback mismatch')
        checks.append(dict(name=name,kind=kind,sha256=expected,passed=True))
    profile=args.output/'NativeIos27StorageProfile.h'
    profile.write_text('/* Generated from actual retained APFS volume UUIDs. */\n#pragma once\n'+''.join(
        f'#define ZETA_IOS27_{w["name"].upper()}_VOLUME_UUID "{w["volume_uuid"]}"\n' for w in windows))
    report=dict(old,image=str(image.resolve()),image_bytes=end,image_sha256=total.hexdigest(),windows=windows,
        preboot_scaffold=True,mount_profile_header=str(profile.resolve()),
        assembled_window_and_policy_readback=checks,all_assembled_regions_verified=True)
    report['mount_requirements']['Preboot']='/private/preboot'
    (args.output/'root-storage.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ['windows','assembled_window_and_policy_readback']},indent=2))

def layout(args):
    r=json.loads(args.roots.read_text());d=json.loads(args.data.read_text())
    tokens=shlex.split(args.boot_args);options={t.split('=',1)[0]:t.partition('=')[2] for t in tokens}
    if any(k in options for k in d['forbidden_bootargs']):raise ValueError('legacy suppression/reset bootarg would invalidate full Data')
    reserve=getattr(args,'log_reserve_mib',1024)
    if options.get('sheng-data-persist')!='2' or options.get('sheng-log-reserve','1024')!=str(reserve):
        raise ValueError('direct Data needs persist2 and the exact explicitly selected log reserve')
    g=overlay_geometry(r['userdata_bytes'],r['image_bytes'],d['logical_bytes'],reserve)
    report=dict(schema='zeta-ios27-host-storage-integration-v1',**g,root_report=str(args.roots),data_report=str(args.data),
        writes=[dict(offset=0,bytes=r['image_bytes'],source=r['image'],sha256=r['image_sha256']),
                dict(offset=g['store_partition_offset'],bytes=d['store_bytes'],source=d['store'],sha256=d['store_sha256'])],
        root_windows_writable=False,boot_args=args.boot_args,boot_policy_pass=True,
        reset_would_destroy_missing_anchor_payload=True,requires_complete_store_before_boot=True,
        expected_native_data_persist_state=2,expected_native_owner_data_stage=4,expected_native_owner_data_readonly=0,
        adt_requirements=['--packed-data-ramdisk','--persistent-data','--root-match-volume-uuid '+r['windows'][0]['volume_uuid']],
        root_isa_conversion_pending=True,cryptex_app_mount_integration_pending=True,phone_modified=False,boot_qualified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('data');d.add_argument('--input',type=Path,required=True);d.add_argument('--input-sha256',required=True)
    d.add_argument('--unixnu',type=Path,required=True);d.add_argument('--output',type=Path,required=True);d.set_defaults(func=data)
    r=sub.add_parser('roots')
    for name in ['os','systemos','appos','unixnu','private-key','public-key','public-header','userdata-facts','output']:
        r.add_argument('--'+name,type=Path,required=True)
    r.set_defaults(func=roots)
    q=sub.add_parser('preboot')
    for name in ['roots','preboot','unixnu','private-key','public-key','output']:q.add_argument('--'+name,type=Path,required=True)
    q.set_defaults(func=preboot)
    l=sub.add_parser('layout')
    for name in ['roots','data','output']:l.add_argument('--'+name,type=Path,required=True)
    l.add_argument('--boot-args',required=True)
    l.add_argument('--log-reserve-mib',type=int,default=1024,
        help='fixed lifetime reserve for this store; must exactly match boot args (default1024)')
    l.set_defaults(func=layout)
    a=p.parse_args();a.func(a)

if __name__=='__main__':main()
