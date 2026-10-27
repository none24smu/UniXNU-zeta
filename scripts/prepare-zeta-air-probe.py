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

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ("workspace","artifact","control","seed-control","output","seed-output"):
        p.add_argument("--"+flag,type=Path,required=True)
    a=p.parse_args();root=a.workspace.resolve();z=Path(__file__).resolve().parents[1]
    artifact=a.artifact.resolve();control=a.control.resolve();oldseed=a.seed_control.resolve()
    out=a.output.resolve();seed=a.seed_output.resolve()
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
    job["Label"]="com.apple.bluetoothd"
    (daemons/"com.apple.bluetoothd.plist").write_bytes(plistlib.dumps(job))
    # Include the expected owner job name for the kernel's mount validation,
    # disabled so it cannot create a second GPU client.
    (daemons/"org.blu-sharky.adrenoprobed.plist").write_bytes(plistlib.dumps({
        "Label":"org.blu-sharky.adrenoprobed","ProgramArguments":["/private/var/ngpu/addons/air-probe/zeta-air-probe"],
        "Disabled":True,"RunAtLoad":False}))
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
    args=tomllib.loads((out/"unixnu.toml").read_text())["entry"][0]["args"]
    assert len(args.encode())<1024 and "zeta-touch-listen2=0" in args
    for source,target in ((seed/"data.dbr","scratch-data.img"),(seed/"kernel.macho.trustcache","kernel.macho.trustcache")):
        run("copy-"+target,"mcopy","-o","-i",out/"payload.img",source,"::/EFI/UniXNU/Payloads/"+target)
    run("fat-check","fsck.fat","-n",out/"payload.img")
    embedded=subprocess.check_output(["mtype","-i",str(out/"payload.img"),"::/EFI/UniXNU/unixnu.toml"])
    assert embedded==(control/"unixnu.toml").read_bytes()
    run("bootimg",root/"UniXNU/unixnu","bootimg","-D",z,"--uefi",root/"uefi-zeta","--fd",
        z/"build/bringup/highmem/dram-high-clockfix.fd","--dtb",z/"build/zeta/zeta.dtb","--ramdisk",out/"payload.img","-o",out/"boot.img")
    report=dict(control=str(control),artifact=meta,ram_boot_only=True,hardware_tested=False,
        preserved=["kernel","ADT","UEFI","boot args","system renderer","shader pack","persistent touch"],
        changes=["isolated AIR probe and public shader fixtures","one temporary launchd job","three static trust entries"],
        sha256={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ("kernel.macho","kernel.macho.adt","unixnu.toml","boot.img")})
    (out/"test-inputs.json").write_text(json.dumps(report,indent=2)+"\n")
    print(out/"boot.img")
if __name__=="__main__":main()
