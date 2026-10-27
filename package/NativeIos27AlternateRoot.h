// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Keep legacy header0 untouched. Only an exact selected, owner-authenticated
// alternate header can expand policy limits. Ops owns real UFS reads, SHA256
// and VROOT signature/block verification; this parser never writes a block.
struct ZetaAlternateRootProfile {
    uint64_t offset;
    uint64_t maxPolicyBytes;
    uint64_t totalPolicyResidentBytes;
    uint64_t allocationPageBytes; // conservative wired-allocation granule, 4K or16K
    uint8_t legacyHeaderSha256[32],alternateHeaderSha256[32];
};
static uint64_t zetaAltU64(const uint8_t *p) {
    uint64_t n=0;for(unsigned i=0;i<8;++i)n|=uint64_t(p[i])<<(8*i);return n;
}
static uint32_t zetaAltU32(const uint8_t *p) {
    return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
}
template<class Ops>
static bool zetaReadAlternateRoot(Ops &ops,uint64_t first,uint64_t last,uint64_t request,
    const ZetaAlternateRootProfile &profile,uint8_t scratch[8192],const char **why)
{
    if(last<first || last>0xffffffffULL || last-first+1>UINT64_MAX/4096) {
        *why="alternate partition bounds";return false;
    }
    uint64_t bytes=(last-first+1)*4096;
    if(profile.allocationPageBytes!=4096 && profile.allocationPageBytes!=16384) {
        *why="alternate allocator granule";return false;
    }
    if(!request || request!=profile.offset || (request&4095) || request>=bytes || 8192>bytes-request) {
        *why="alternate offset not selected profile";return false;
    }
    if(!ops.read(first,1,scratch)){*why="legacy header read";return false;}
    uint8_t hash[32];ops.sha256(scratch,4096,hash);
    if(memcmp(hash,profile.legacyHeaderSha256,32) || memcmp(scratch,"SHNGROOT",8)) {
        *why="legacy header differs from confirmed profile";return false;
    }
    uint64_t oldBytes=zetaAltU64(scratch+16);
    if(zetaAltU32(scratch+8)!=1 || zetaAltU32(scratch+12)<1 || zetaAltU32(scratch+12)>4 ||
       oldBytes<4096 || (oldBytes&4095) || oldBytes>bytes || oldBytes>UINT64_MAX-4194304 || request<oldBytes+4194304) {
        *why="alternate header overlaps legacy prefix/guard";return false;
    }
    if(!ops.read(first+request/4096,2,scratch)){*why="alternate header/envelope read";return false;}
    ops.sha256(scratch,4096,hash);
    if(memcmp(hash,profile.alternateHeaderSha256,32) || !ops.authenticate(scratch,scratch+4096)) {
        *why="alternate owner header authentication";return false;
    }
    if(memcmp(scratch,"SHNGROOT",8) || zetaAltU32(scratch+8)!=1) {
        *why="alternate header format";return false;
    }
    unsigned count=zetaAltU32(scratch+12);
    if(count<2 || count>4){*why="alternate header window count";return false;}
    uint64_t resident=0;
    for(unsigned i=0;i<count;++i) {
        const uint8_t *entry=scratch+24+128*i;
        uint64_t size=zetaAltU64(entry+40),policy=zetaAltU64(entry+96);
        uint64_t page=profile.allocationPageBytes,mask=page-1;
        if(!size || size>bytes || policy!=544+((size+4095)/4096)*32 ||
            policy>profile.maxPolicyBytes || policy>UINT64_MAX-2*page) {
            *why="alternate per-window policy budget";return false;
        }
        uint64_t allocation=((policy+mask)&~mask)+page;
        if(allocation>profile.totalPolicyResidentBytes || resident>profile.totalPolicyResidentBytes-allocation) {
            *why="alternate total policy RAM budget";return false;
        }
        resident+=allocation;
    }
    return true; // The ordinary RootLayout parser still validates every window/policy bound.
}
