#!/usr/bin/env python3
"""Explicit opt-in compile contract for the full-stock iOS27 storage profile.

Default is disabled. This prepares/checks host inputs; it never edits another
build script, compiles a kernel, selects a boot entry or touches a device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

BOARD=Path(__file__).resolve().parents[1]
SOURCES=[BOARD/'package/NativeIos27CryptexMount.c',BOARD/'package/NativeIos27CryptexVolumes.cpp',BOARD/'package/NativeIos27DataStoreGuard.h']

def hash_file(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def retarget(arguments, old_source, new_source, destination, extra):
    result=[];i=0;replaced=0
    while i<len(arguments):
        value=arguments[i]
        if value==old_source:result.append(str(new_source));replaced+=1
        elif value=='-o':result+=['-o',str(destination)];i+=1
        elif value in ['-MF','-MJ','-MT','-MQ']:i+=1
        elif value not in ['-MD','-MMD','-MP']:result.append(value)
        i+=1
    if replaced!=1:raise ValueError('compile record must identify exactly one source')
    return result+extra

def check(enabled, roots=None, data=None, metadata=None, header=None, providers=None, provider_root=None, guard_export=None):
    if not enabled:return dict(profile_enabled=False,kern_exec_defines=['-DXNU_IOS27_CRYPTEXES=0'],helper_objects_required=[],runtime_verified=False)
    if not all(x is not None for x in [roots,data,metadata,header,providers,guard_export]):raise ValueError('explicit full27 profile requires root/Data/metadata/header/provider/guard evidence')
    if (not guard_export.get('require_existing_exact_store') or not guard_export.get('original_source_unchanged') or
            hash_file(Path(guard_export['output']))!=guard_export['output_sha256'] or
            hash_file(Path(guard_export['guard_header']))!=guard_export['guard_header_sha256']):
        raise ValueError('full stock requires the exact resume-only NativeRamBlock export')
    if not providers.get('all_driver_pins_match') or not providers.get('all_source_trees_clean'):
        raise ValueError('native UFS/RAM providers must match exact pinned clean source')
    hashes=({str(provider_root/p):v for p,v in providers['relative_source_files_sha256'].items()}
            if provider_root else providers['source_files_sha256'])
    for path,expected in hashes.items():
        if hash_file(Path(path))!=expected:raise ValueError('native provider source/header hash changed: '+path)
    if (not roots.get('all_three_namespaces_preserved') or not roots.get('preboot_scaffold') or
            {x['name'] for x in roots['windows']}!={'OS','SystemOS','AppOS','Preboot'}):
        raise ValueError('require complete OS/SystemOS/AppOS immutable windows and original symlink Preboot scaffold')
    if not data.get('store_full_data_readback_passed') or not data.get('anchor_apfs_metadata_readback_passed') or data.get('loader_limit_changed'):
        raise ValueError('bounded full Data direct-store inputs not qualified')
    if not metadata.get('normalized_file_metadata_qualified') or metadata.get('failures'):
        raise ValueError('native file metadata preservation/normalization gate not passed')
    definitions=dict(re.findall(r'#define ZETA_IOS27_(\w+)_VOLUME_UUID "([0-9A-F-]{36})"',header))
    for w in roots['windows']:
        if definitions.get(w['name'].upper())!=w['volume_uuid']:raise ValueError('header/root volume identity mismatch')
    return dict(profile_enabled=True,kern_exec_defines=['-DXNU_IOS27_CRYPTEXES=1'],
        helper_objects_required=['NativeIos27CryptexMount.o','NativeIos27CryptexVolumes.o'],
        required_existing_defines={'XNU_OWNER_DATA_MOUNT':1,'XNU_NATIVE_RAM_BLOCK':1,'XNU_NATIVE_UFS_VERIFIED_ROOT':1,'XNU_NATIVE_UFS_OWNER_ROOT':1},
        source_namespace_mounts={'OS':'/','Preboot':'/private/preboot','SystemOS':'/System/Cryptexes/OS','AppOS':'/System/Cryptexes/App'},
        default_boot_profile_changed=False,legacy_watchdog_suppression_call_enabled=False,
        native_ram_source_override=guard_export['output'],resume_only_store_guard_required=True,
        loader_cache_namespace_audit_pending=True,compiled_kernel_verified=False,runtime_verified=False)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--enable-full-stock27',action='store_true')
    for name in ['roots','data','metadata-gate','profile-header','provider-manifest','provider-source-root','guard-export','bsd-record','storage-command-record']:
        p.add_argument('--'+name,type=Path)
    p.add_argument('--output-directory',type=Path,required=True)
    a=p.parse_args();a.output_directory.mkdir(parents=True,exist_ok=True)
    read=lambda path:json.loads(path.read_text()) if path else None
    r=check(a.enable_full_stock27,read(a.roots),read(a.data),read(a.metadata_gate),a.profile_header.read_text() if a.profile_header else None,read(a.provider_manifest),a.provider_source_root,read(a.guard_export))
    r['sources_sha256']={str(x.relative_to(BOARD)):hash_file(x) for x in SOURCES}
    r['profile_header_sha256']=hash_file(a.profile_header) if a.profile_header else None
    r['provider_manifest_sha256']=hash_file(a.provider_manifest) if a.provider_manifest else None
    r['compile_examples']={
        'mount':'retarget the ACTUAL BSD kern_exec.o.json arguments to package/NativeIos27CryptexMount.c; preserve target/sysroot/kernel includes/defines; add -I <generated-profile-directory>',
        'volume':'retarget the ACTUAL storage ufs-owner-root.command.json arguments to package/NativeIos27CryptexVolumes.cpp; preserve its IOKit KDK reserved-slot/target/alignment/verified-UFS ABI flags',
        'link':'add both objects to the same final kernel/archive as NativeUfs and NativeRamBlock; require both exported helper symbols; regenerate native IOStorage/NativeRamBlock from pinned source',
        'native_ram':'select the exact native_ram_source_override export for full27 only; preserve its ordinary NativeRamBlock compile/IOKit ABI command; never substitute the legacy auto-initializing source for the metadata-only anchor',
        'patch':'apply patches/xnu-12377/zzzz-native-ios27-cryptexes.patch after existing owner-Data and boot-progress patches; define XNU_IOS27_CRYPTEXES only for explicitly selected full27 target'}
    commands=[]
    if a.enable_full_stock27 and a.bsd_record:
        record=read(a.bsd_record);commands.append(dict(directory=record['directory'],arguments=retarget(record['arguments'],record['file'],SOURCES[0],a.output_directory/'NativeIos27CryptexMount.o',['-I',str(a.profile_header.parent)])))
    if a.enable_full_stock27 and a.storage_command_record:
        args=read(a.storage_command_record);old=[x for x in args if x.endswith('/ufs-owner-root.cpp')]
        if len(old)!=1:raise ValueError('require the actual storage owner-root C++ compile command')
        commands.append(dict(arguments=retarget(args,old[0],SOURCES[1],a.output_directory/'NativeIos27CryptexVolumes.o',[])))
    r['actual_compile_records_supplied']=len(commands)==2 if a.enable_full_stock27 else False
    r['compile_commands']=commands;r['phone_modified']=False
    (a.output_directory/'storage-profile-contract.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r,indent=2))

if __name__=='__main__':main()
