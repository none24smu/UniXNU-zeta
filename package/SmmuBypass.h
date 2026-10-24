// SPDX-License-Identifier: BSD-2-Clause-Patent
// Pass-through stream mapping in the firmware-managed apps SMMU, for a device whose DMA must reach physical memory
// (not a page-table mapping, not an Adreno context). This is the sequence Linux's qcom_smmu bypass quirk describes and the
// UFS driver already uses on this board (docs/native-ufs.md): the last context bank (SCTLR=0, CBAR.TYPE=S1_TRANS_S2_BYPASS,
// CBA2R.VA64=1) is shared by every bypass stream; a stream maps to it with S2CR TYPE=TRANSLATE (a TYPE=BYPASS S2CR reads
// back as FAULT on this firmware) and S2CR is written before SMR. Unlike the UFS planner this one lets several streams share
// the bank. Pure planning/configuration over register callbacks; host-tested by TouchBoardTests.c (UniXNU-sheng, copied unchanged
// for zeta package/TouchProbe.cpp).
#ifndef SHENG_SMMU_BYPASS_H
#define SHENG_SMMU_BYPASS_H
#include <stdint.h>

struct smmu_io {
    void *ctx;
    uint32_t (*rd)(void *ctx, unsigned offset);
    void (*wr)(void *ctx, unsigned offset, uint32_t value);   // must complete an MMIO barrier before returning
};
struct smmu_plan {
    unsigned slot, bank, pages;
    int reuse;               // the stream already maps to the bank
    int bank_ready;          // another stream (or an earlier run) already left the bank in bypass state
    const char *error;
};
static inline unsigned smmu_bits(unsigned code) {
    switch (code) {case 0: return 32; case 1: return 36; case 2: return 40; case 3: return 42; case 4: return 44; case 5: return 48; default: return 0;}
}
// dma/bytes: the physical range the device will access; refused when it exceeds the input, output or intermediate width.
static inline struct smmu_plan smmu_plan_bypass(const struct smmu_io *io, uint16_t stream, uint64_t dma, uint64_t bytes) {
    struct smmu_plan p = {0xffffffffu, 0, 0, 0, 0, 0};
    uint32_t idr0 = io->rd(io->ctx, 0x20), idr1 = io->rd(io->ctx, 0x24), idr2 = io->rd(io->ctx, 0x28);
    unsigned count = idr0 & 255;
    if (!(idr0 & (1u << 30)) || !(idr2 & (1u << 12))) {p.error = "SMMU AArch64 stage 1 unsupported"; return p;}
    for (unsigned shift = 0; shift <= 8; shift += 4) {
        unsigned bits = smmu_bits((idr2 >> shift) & 15);
        if (!bits || !bytes || dma >= (1ull << bits) || bytes > (1ull << bits) - dma) {p.error = "DMA exceeds SMMU address width"; return p;}
    }
    unsigned banks = idr1 & 255;
    p.pages = 1u << (((idr1 >> 28) & 7) + 1);
    if ((idr1 >> 31) || !count || p.pages > 128 || banks < 2 || banks > 128 || (p.pages + banks) * 4096u > 0xd0000u) {
        p.error = "unsupported SMMU geometry"; return p;
    }
    if (count > 128) count = 128;   // the firmware's reliably accessible groups only
    p.bank = banks - 1;
    unsigned matches = 0, sharing = 0;
    for (unsigned i = 0; i < count; ++i) {
        uint32_t smr = io->rd(io->ctx, 0x800 + 4 * i);
        if (!(smr & 0x80000000u)) {if (p.slot == 0xffffffffu) p.slot = i; continue;}
        uint32_t s2cr = io->rd(io->ctx, 0xc00 + 4 * i);
        uint32_t mask = (smr >> 16) & 0x7fff;
        int ourBank = ((s2cr >> 16) & 3) == 0 && (s2cr & 255) == p.bank;
        if (((smr ^ stream) & 0xffff & ~mask) == 0) {
            if (++matches > 1 || mask || !ourBank) {p.slot = i; p.error = "conflicting stream mapping"; return p;}
            p.reuse = 1; p.slot = i;
        } else if (ourBank) {
            ++sharing;
        }
    }
    uint32_t sctlr = io->rd(io->ctx, (p.pages + p.bank) * 4096u);
    uint32_t cbar = io->rd(io->ctx, 0x1000 + 4 * p.bank), cba2r = io->rd(io->ctx, 0x1800 + 4 * p.bank);
    p.bank_ready = (sctlr == 0 && cbar == 0x10000 && (cba2r & ~1u) == 0 && (cba2r & 1u));
    if ((sctlr & 1) || ((sharing || p.reuse) && !p.bank_ready)) {p.error = "reserved context bank is not a bypass bank"; return p;}
    if (p.slot == 0xffffffffu) p.error = "no free stream-match group";
    return p;
}
static inline const char *smmu_configure_bypass(const struct smmu_io *io, const struct smmu_plan *p, uint16_t stream) {
    if (p->error) return p->error;
    unsigned cb = (p->pages + p->bank) * 4096u;
    if (!p->bank_ready) {
        io->wr(io->ctx, cb, 0);
        io->wr(io->ctx, 0x1800 + 4 * p->bank, 1);
        io->wr(io->ctx, 0x1000 + 4 * p->bank, 0x10000);
    }
    if (io->rd(io->ctx, cb) != 0 || io->rd(io->ctx, 0x1800 + 4 * p->bank) != 1 || io->rd(io->ctx, 0x1000 + 4 * p->bank) != 0x10000)
        return "SMMU bypass bank readback";
    if (!p->reuse) {
        io->wr(io->ctx, 0xc00 + 4 * p->slot, p->bank);
        if (io->rd(io->ctx, 0xc00 + 4 * p->slot) != p->bank) return "SMMU stream context readback";
        io->wr(io->ctx, 0x800 + 4 * p->slot, 0x80000000u | stream);
    }
    if (io->rd(io->ctx, 0x800 + 4 * p->slot) != (0x80000000u | stream) || io->rd(io->ctx, 0xc00 + 4 * p->slot) != p->bank)
        return "SMMU stream mapping readback";
    return 0;
}
#endif
