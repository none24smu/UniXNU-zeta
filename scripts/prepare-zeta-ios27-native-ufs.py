#!/usr/bin/env python3
"""Export a separate pinned UFS provider for opt-in authenticated alt headers.

Default/header0 behavior and every existing provider stay unchanged. An enabled
profile requires actual legacy-header readback plus owner-signed new header
evidence. Host fixture exports cannot compile for AArch64 deployment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

BOARD=Path(__file__).resolve().parents[1]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source','sm8350-patch','provider-manifest','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',type=Path);p.add_argument('--host-fixture',action='store_true')
    a=p.parse_args();pins=json.loads(a.provider_manifest.read_text());relative=pins['relative_source_files_sha256']
    expected=relative.get('drivers/NativeUfs/NativeUfs.cpp')
    if not expected or sha(a.source/'NativeUfs.cpp')!=expected:raise ValueError('UFS source must match the pinned provider manifest')
    for name,expected_hash in relative.items():
        if name.startswith('drivers/NativeUfs/') and sha(a.source/Path(name).name)!=expected_hash:
            raise ValueError('pinned UFS source/header changed: '+name)
    if sha(a.sm8350_patch)!=relative.get('patches/drivers/NativeUfs-sm8350.patch'):raise ValueError('adapter patch hash changed')
    a.output.mkdir(parents=True,exist_ok=False)
    shutil.copytree(a.source,a.output/'NativeUfs',ignore=shutil.ignore_patterns('.git','build'),dirs_exist_ok=True)
    driver=(a.output/'NativeUfs').resolve()
    with tempfile.TemporaryDirectory(prefix='zeta-alt-ufs-') as tmp:
        command=['git','apply','--unsafe-paths','--directory',str(driver)]
        subprocess.run(command+[str(a.sm8350_patch.resolve())],cwd=tmp,check=True)
        subprocess.run(command+['--reverse','--check',str(a.sm8350_patch.resolve())],cwd=tmp,check=True)
    shutil.copyfile(BOARD/'package/NativeIos27AlternateRoot.h',driver/'NativeIos27AlternateRoot.h')
    path=driver/'RootLayout.h';text=path.read_text()
    marker='static bool findRootLayout (RootLayout *layout, const char **why)'
    declarations='''#if defined(NATIVE_IOS27_ALT_MANIFEST) && NATIVE_IOS27_ALT_MANIFEST
#if !defined(NATIVE_VERIFIED_BLOCK) || !NATIVE_VERIFIED_BLOCK
#error Alternate root selection requires real owner verification
#endif
#include "NativeIos27AlternateRoot.h"
#include "NativeIos27AlternateRootProfile.h"
static bool gIos27AlternateHeaderActive = false;
#endif

'''
    if text.count(marker)!=1:raise ValueError('RootLayout entry not unique')
    text=text.replace(marker,declarations+marker)
    old='''  if (hostRead4k (0, layout->userdataFirst, 1, gScratch) != kIOReturnSuccess) {
    *why = "userdata first block read";
    return false;
  }'''
    replacement='''#if defined(NATIVE_IOS27_ALT_MANIFEST) && NATIVE_IOS27_ALT_MANIFEST
  gIos27AlternateHeaderActive = false;
  uint64_t requestedHeader = 0;
  PE_parse_boot_argn ("zeta-root-manifest-offset", &requestedHeader, sizeof (requestedHeader));
  if (requestedHeader) {
    if (PAGE_SIZE > kZetaAlternateRootProfile.allocationPageBytes) {
      *why="alternate allocator granule exceeds selected profile";return false;
    }
    struct AlternateOps {
      bool read (uint64_t lba, unsigned n, void *out) { return hostRead4k (0,lba,n,out)==kIOReturnSuccess; }
      void sha256 (const void *p,size_t n,uint8_t out[32]) {
        SHA256_CTX c;SHA256_Init(&c);SHA256_Update(&c,p,n);SHA256_Final(out,&c);
      }
      bool authenticate (const uint8_t *header,const uint8_t *policy) {
        vr_view view = {};
        return vr_open(policy,576,verified_root_key,1,&vr_xnu_crypto,&view)==VR_OK &&
          view.image_bytes==4096 && view.block_count==1 &&
          !memcmp(view.volume_uuid,kZetaAlternateHeaderPolicyUuid,16) &&
          vr_verify_block(&view,0,header,4096,&vr_xnu_crypto)==VR_OK;
      }
    } operations;
    if (!zetaReadAlternateRoot(operations,layout->userdataFirst,layout->userdataLast,
                              requestedHeader,kZetaAlternateRootProfile,gScratch,why)) return false;
    gIos27AlternateHeaderActive = true;
  } else
#endif
'''+old
    if text.count(old)!=1:raise ValueError('legacy header read not unique')
    path.write_text(text.replace(old,replacement))
    text=path.read_text();old='w.policyBytes > 128ULL * 1024 * 1024'
    if text.count(old)!=1:raise ValueError('RootLayout policy bound not unique')
    budget='''        uint64_t ios27LayoutPolicyLimit = 128ULL * 1024 * 1024;
#if defined(NATIVE_IOS27_ALT_MANIFEST) && NATIVE_IOS27_ALT_MANIFEST
        if (gIos27AlternateHeaderActive) ios27LayoutPolicyLimit = kZetaAlternateRootProfile.maxPolicyBytes;
#endif
'''
    anchor='        // An envelope is untrusted until vr_open verifies its signature and hash'
    if text.count(anchor)!=1:raise ValueError('layout budget insertion not unique')
    text=text.replace(anchor,budget+anchor).replace(old,'w.policyBytes > ios27LayoutPolicyLimit')
    old_round='uint64_t rounded = (w.policyBytes + 4095) & ~4095ULL;'
    new_round='''uint64_t policyMask = 4095;
#if defined(NATIVE_IOS27_ALT_MANIFEST) && NATIVE_IOS27_ALT_MANIFEST
          if (gIos27AlternateHeaderActive) policyMask = kZetaAlternateRootProfile.allocationPageBytes-1;
#endif
          uint64_t rounded = (w.policyBytes + policyMask) & ~policyMask;'''
    if text.count(old_round)!=1:raise ValueError('policy read granule bound not unique')
    text=text.replace(old_round,new_round).replace('((o.policyBytes + 4095) & ~4095ULL)','((o.policyBytes + policyMask) & ~policyMask)')
    path.write_text(text)
    path=driver/'NativeUfs.cpp';text=path.read_text();old='manifestBytes > 128ULL * 1024 * 1024'
    new='manifestBytes > ios27PolicyLimit'
    if text.count(old)!=1:raise ValueError('pinned disk policy bound not unique')
    insert='''  uint64_t ios27PolicyLimit = 128ULL * 1024 * 1024;
#if defined(NATIVE_IOS27_ALT_MANIFEST) && NATIVE_IOS27_ALT_MANIFEST
  if (gIos27AlternateHeaderActive) ios27PolicyLimit = kZetaAlternateRootProfile.maxPolicyBytes;
#endif
'''
    anchor='  if (!diskPolicyAbsolute || (diskPolicyAbsolute & 4095) ||'
    if text.count(anchor)!=1:raise ValueError('disk policy budget insertion not unique')
    path.write_text(text.replace(anchor,insert+anchor).replace(old,new))
    enabled=bool(a.profile)
    if enabled:
        cfg=json.loads(a.profile.read_text())
        if not cfg.get('legacy_live_header_readback_verified') and not a.host_fixture:
            raise ValueError('do not enable alternate layout before confirmed legacy device readback')
        if not cfg.get('owner_header_signature_verified') or (not cfg.get('all_payload_readbacks_passed') and not (a.host_fixture and cfg.get('fixture'))):
            raise ValueError('signed header and all final payload readbacks required')
        if not (0<cfg['max_policy_bytes']<=384<<20 and cfg['max_policy_bytes']+4096<=cfg['total_policy_resident_bytes']<=768<<20):
            raise ValueError('selected policy budget exceeds bounded preparation profile')
        if cfg.get('allocation_page_bytes',16384) not in [4096,16384]:raise ValueError('unsupported allocator granule')
        def array(value):return '{'+','.join('0x'+value[i:i+2] for i in range(0,len(value),2))+'}'
        content=('#pragma once\n'+('#if defined(__aarch64__)\n#error Host fixture profile cannot deploy\n#endif\n' if a.host_fixture else '')+
            'static const ZetaAlternateRootProfile kZetaAlternateRootProfile = {'+
            f'{cfg["offset"]}ULL,{cfg["max_policy_bytes"]}ULL,{cfg["total_policy_resident_bytes"]}ULL,{cfg.get("allocation_page_bytes",16384)}ULL,'+
            array(cfg['legacy_header_sha256'])+','+array(cfg['alternate_header_sha256'])+'};\n'+
            'static const uint8_t kZetaAlternateHeaderPolicyUuid[16] = '+array(cfg['header_policy_uuid_hex'])+';\n')
        (driver/'NativeIos27AlternateRootProfile.h').write_text(content)
    report=dict(schema='zeta-ios27-native-ufs-alternate-export-v1',source_commit=next(x['expected_gitlink'] for x in pins['driver_pins'] if x['driver']=='NativeUfs'),
        source_unchanged=True,output=str(driver),sm8350_patch_already_applied=True,
        required_defines=['-DNATIVE_IOS27_ALT_MANIFEST='+('1' if enabled else '0')],
        default_header0_limit_bytes=128<<20,default_existing_provider_changed=False,
        selected_header_authenticated_with_existing_owner_key=True,host_fixture=a.host_fixture,
        compiled_kernel_verified=False,phone_modified=False,
        source_files_sha256={str(x.relative_to(driver)):sha(x) for x in sorted(driver.iterdir()) if x.suffix in ['.h','.cpp']})
    (a.output/'native-ufs-export.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='source_files_sha256'},indent=2))

if __name__=='__main__':main()
