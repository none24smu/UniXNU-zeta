#!/usr/bin/env python3
"""Prepare a RAM-only AIR probe image from a verified control and signed artifact.

No device operations. Retains the control's kernel, ADT, config, system renderer
and shader pack. Adds an isolated launchd probe and its static trust entries.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tomllib
import uuid

def sign_owner_cache(data, template):
    """Rebuild the existing ad-hoc detached signature for the owner RAM cache.

    Retain requirements/special slots and both SHA-1/SHA-256 directories. The
    new SHA-256 CDHash must be explicitly admitted by this image's static trust
    bundle; page validation remains enabled.
    """
    magic,length,count=struct.unpack_from(">3I",template)
    assert magic==0xfade0cc0 and length==len(template)
    blobs=[];cdhash=None
    for i in range(count):
        kind,offset=struct.unpack_from(">II",template,12+8*i)
        blob_magic,size=struct.unpack_from(">II",template,offset)
        blob=bytearray(template[offset:offset+size]);assert len(blob)==size
        if blob_magic==0xfade0c02:
            _,_,version,flags,hash_offset,ident,special,slots,limit,hash_size,hash_type,platform,page=struct.unpack_from(">9I4B",blob)
            assert flags&2 and page==12 and platform==0 and version==0x20500
            assert (hash_type,hash_size) in ((1,20),(2,32))
            assert hash_offset+slots*hash_size==len(blob)
            name=b"zeta-air-owner-launchd-cache\0"
            end=hash_offset-special*hash_size
            assert ident+len(name)<=end
            blob[ident:end]=name+b"\0"*(end-ident-len(name))
            slots=(len(data)+4095)//4096
            blob=blob[:hash_offset]
            digest=hashlib.sha1 if hash_type==1 else hashlib.sha256
            blob.extend(b"".join(digest(data[n:n+4096]).digest() for n in range(0,len(data),4096)))
            struct.pack_into(">I",blob,4,len(blob))
            struct.pack_into(">II",blob,28,slots,len(data))
            # The template uses the 32-bit codeLimit and no scatter/pre-encrypt
            # table. Refuse a different layout rather than retaining stale data.
            assert struct.unpack_from(">IIQ",blob,44)==(0,0,0)
            if hash_type==2:cdhash=hashlib.sha256(blob).digest()[:20]
        elif kind==0x10000:
            assert blob==struct.pack(">II",0xfade0b01,8), "Only ad-hoc signatures are supported"
        blobs.append((kind,bytes(blob)))
    assert cdhash is not None
    cursor=12+8*len(blobs);indices=[]
    for kind,blob in blobs:indices.append(struct.pack(">II",kind,cursor));cursor+=len(blob)
    return struct.pack(">III",magic,cursor,len(blobs))+b"".join(indices)+b"".join(blob for _,blob in blobs),cdhash

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ("workspace","artifact","control","seed-control","output","seed-output"):
        p.add_argument("--"+flag,type=Path,required=True)
    p.add_argument("--disk-jobs-kernel",type=Path,
                   help="Kernel directory containing kernel.macho and its .adt, with the opt-in RAM xpc view")
    a=p.parse_args();root=a.workspace.resolve();z=Path(__file__).resolve().parents[1]
    artifact=a.artifact.resolve();control=a.control.resolve();oldseed=a.seed_control.resolve()
    out=a.output.resolve();seed=a.seed_output.resolve()
    cache_hash=None
    if a.disk_jobs_kernel:
        kernel=a.disk_jobs_kernel/"kernel.macho"
        assert b"zeta-air: disk job view mount status" in kernel.read_bytes(), "Missing compiled AIR boot hook; use zeta_userland_trust_defconfig"
        symbols=subprocess.check_output(["llvm-nm","--defined-only",str(kernel)],text=True)
        for symbol in ("_sheng_boot_watchdog_policy","_native_bindfs_boot_mount","_native_gpu_addon2_stage"):
            assert any(line.split()[-1]==symbol for line in symbols.splitlines() if line.split()), "Missing userland profile symbol: "+symbol
    meta=json.loads((artifact/"trust.json").read_text());assert len(meta["files"])==3
    assert meta["userland_ref"]=="3278f7f01796e74ecd634c0d348d2b255a37658f"
    for name,info in meta["files"].items():
        assert Path(name).name==name and len(bytes.fromhex(info["cdhash"]))==20
        assert hashlib.sha256((artifact/name).read_bytes()).hexdigest()==info["sha256"]
    out.mkdir(exist_ok=False);seed.mkdir(exist_ok=False)
    shutil.copytree(oldseed/"overlay",seed/"overlay")
    probe=seed/"overlay/ngpu/addons/air-probe";probe.mkdir()
    for name in (*meta["files"],"argbuf_set.bc","argbuf_direct.bc"):
        shutil.copy2(artifact/name,probe/name)
        (probe/name).chmod(0o755 if name in meta["files"] else 0o644)
    # Bindfs union lookup is reliable for an existing job name even when
    # readdir does not expose a newly added name. One job only, to avoid two
    # competing probes. This changes only this experimental RAM seed.
    daemons=seed/"overlay/ngpu/daemons";daemons.mkdir(exist_ok=True)
    job=plistlib.loads((artifact/"org.unixnu.zeta.air-probe.plist").read_bytes())
    job["Label"]="com.apple.iomfb_fdr_loader"
    # Bluetooth is disabled by sheng-lite=1. The nonessential FDR loader is
    # an existing System RunAtLoad job that remains enabled in this profile.
    assert job["Label"] not in (z/"package/BootWatchdogPolicy.c").read_text()
    job["LimitLoadToSessionType"]="System"
    (daemons/"com.apple.iomfb_fdr_loader.plist").write_bytes(plistlib.dumps(job))
    # Include the expected owner job name for the kernel's mount validation,
    # disabled so it cannot create a second GPU client.
    (daemons/"org.blu-sharky.adrenoprobed.plist").write_bytes(plistlib.dumps({
        "Label":"org.blu-sharky.adrenoprobed","ProgramArguments":["/private/var/ngpu/addons/air-probe/zeta-air-probe"],
        "Disabled":True,"RunAtLoad":False}))
    if a.disk_jobs_kernel:
        xpc=seed/"overlay/ngpu/xpc";xpc.mkdir()
        original_xpc=root/"work/mount-os/root/System/Library/xpc"
        assert (original_xpc/"launchd.plist").is_file()
        for path in original_xpc.iterdir():
            assert path.is_file(),path
            shutil.copy2(path,xpc/path.name)
        # iOS26's cache parser has a fatal missing-cache path. Preserve the
        # consolidated cache and every other job/configuration; override only
        # the same enabled probe slot in this owner RAM view. Re-sign the
        # changed cache and explicitly trust its new owner CodeDirectory.
        cache_path=xpc/"launchd.plist";cache=plistlib.loads(cache_path.read_bytes())
        key="/System/Library/LaunchDaemons/com.apple.iomfb_fdr_loader.plist"
        assert key in cache["LaunchDaemons"]
        original=plistlib.loads(cache_path.read_bytes());cache["LaunchDaemons"][key]=job
        for name,value in original.items():
            if name!="LaunchDaemons":assert cache[name]==value
        assert set(cache["LaunchDaemons"])==set(original["LaunchDaemons"])
        assert all(cache["LaunchDaemons"][k]==v for k,v in original["LaunchDaemons"].items() if k!=key)
        cache_path.write_bytes(plistlib.dumps(cache,fmt=plistlib.FMT_BINARY,sort_keys=False))
        assert plistlib.loads(cache_path.read_bytes())["LaunchDaemons"][key]==job
        signature,cache_hash=sign_owner_cache(cache_path.read_bytes(),(xpc/"launchd.plist.sig").read_bytes())
        (xpc/"launchd.plist.sig").write_bytes(signature)
        assert (xpc/"extensions.plist").is_file()
    shutil.copy2(oldseed/"preferences.plist",seed/"preferences.plist")
    spec=importlib.util.spec_from_file_location("trust",z/"scripts/make-zeta-trust-bundle.py")
    trust=importlib.util.module_from_spec(spec);spec.loader.exec_module(trust)
    old=(oldseed/"kernel.macho.trustcache").read_bytes();assert trust.valid_like_the_loader(old)
    assert struct.unpack_from("<II",old)==(1,8)
    count=struct.unpack_from("<I",old,28)[0]
    entries={old[32+i*24:52+i*24]:old[52+i*24:56+i*24] for i in range(count)}
    original=dict(entries)
    for info in meta["files"].values():
        h=bytes.fromhex(info["cdhash"]);assert h not in entries
        entries[h]=bytes([2,0,0,0])
    if cache_hash is not None:
        assert cache_hash not in entries
        entries[cache_hash]=bytes([2,0,0,0])
    ordered=sorted(entries);identifier=uuid.uuid5(uuid.NAMESPACE_URL,"zeta-air:"+hashlib.sha256(b"".join(ordered)).hexdigest())
    new=struct.pack("<III16sI",1,8,2,identifier.bytes,len(entries))+b"".join(h+entries[h] for h in ordered)
    assert trust.valid_like_the_loader(new) and all(entries[h]==attrs for h,attrs in original.items())
    (seed/"kernel.macho.trustcache").write_bytes(new)
    def run(label,*command):
        with (out/(label+".log")).open("w") as log:
            subprocess.run(list(map(str,command)),cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
    run("data-seed","python3",z/"scripts/make-zeta-data-seed.py","--os-root",root/"work/mount-os/root",
        "--volume-uuid","288C85FB-CE8C-478B-994A-48109BA10DF0","--output",seed/"data.dbr","--size-mib","1024",
        "--kernel",root/"work/tools/apfs-guest/vmlinuz","--module",root/"work/tools/linux-apfs-rw/apfs.ko",
        "--busybox",root/"work/tools/apfs-guest/initramfs/bin/busybox","--mkapfs",root/"work/tools/apfsprogs-src/mkapfs/mkapfs",
        "--overlay",seed/"overlay","--preferences",seed/"preferences.plist","--skip-setup")
    for name in ("payload.img","kernel.macho","kernel.macho.adt","unixnu.toml"):shutil.copy2(control/name,out/name)
    if a.disk_jobs_kernel:
        for name in ("kernel.macho","kernel.macho.adt"):
            shutil.copy2(a.disk_jobs_kernel/name,out/name)
            run("copy-"+name,"mcopy","-o","-i",out/"payload.img",out/name,"::/EFI/UniXNU/Payloads/"+name)
        config=(out/"unixnu.toml").read_text()
        old_args=tomllib.loads(config)["entry"][0]["args"]
        assert "zeta-air-probe=" not in old_args
        config=config.replace(old_args,old_args+" zeta-air-probe=1",1)
        (out/"unixnu.toml").write_text(config)
        run("copy-config","mcopy","-o","-i",out/"payload.img",out/"unixnu.toml","::/EFI/UniXNU/unixnu.toml")
    args=tomllib.loads((out/"unixnu.toml").read_text())["entry"][0]["args"]
    assert len(args.encode())<1024 and "zeta-touch-listen2=0" in args
    if a.disk_jobs_kernel:assert args.endswith(" zeta-air-probe=1")
    for source,target in ((seed/"data.dbr","scratch-data.img"),(seed/"kernel.macho.trustcache","kernel.macho.trustcache")):
        run("copy-"+target,"mcopy","-o","-i",out/"payload.img",source,"::/EFI/UniXNU/Payloads/"+target)
    run("fat-check","fsck.fat","-n",out/"payload.img")
    embedded=subprocess.check_output(["mtype","-i",str(out/"payload.img"),"::/EFI/UniXNU/unixnu.toml"])
    assert embedded==(out/"unixnu.toml").read_bytes()
    run("bootimg",root/"UniXNU/unixnu","bootimg","-D",z,"--uefi",root/"uefi-zeta","--fd",
        z/"build/bringup/highmem/dram-high-clockfix.fd","--dtb",z/"build/zeta/zeta.dtb","--ramdisk",out/"payload.img","-o",out/"boot.img")
    report=dict(control=str(control),artifact=meta,ram_boot_only=True,hardware_tested=False,
        preserved=["kernel","ADT","UEFI","boot args","system renderer","shader pack","persistent touch"],
        changes=["isolated AIR probe and public shader fixtures","one temporary launchd job","three static trust entries"],
        sha256={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ("kernel.macho","kernel.macho.adt","unixnu.toml","boot.img")})
    if a.disk_jobs_kernel:
        report["preserved"]=["UEFI","system renderer","shader pack","persistent touch"]
        report["changes"] += ["opt-in RAM xpc view and kernel hook; consolidated cache changes only the FDR-loader job to the probe; matching owner detached signature and fourth static trust entry"]
        report["cache_cdhash"]=cache_hash.hex()
    (out/"test-inputs.json").write_text(json.dumps(report,indent=2)+"\n")
    print(out/"boot.img")
if __name__=="__main__":main()
