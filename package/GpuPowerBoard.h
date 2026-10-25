// SPDX-License-Identifier: BSD-2-Clause-Patent
// sheng package/GpuPowerBoard.h on zeta's SM8350 (lahaina) Adreno 660: the same staged, gated reads, with the board facts taken
// from the stock Surface Duo 2 firmware (vendor_boot DTB Lahaina V2.1, vendor /lib/modules/5.4-gki gpucc-lahaina.ko, the
// vendor_boot ramdisk's gcc-lahaina.ko and clk-qcom.ko). Nothing here touches hardware; GpuPowerProbe.cpp owns the MMIO.
// Host-tested by scripts/tests/test_gpu_power_board.py.
//
// Why staged (sheng): the GPU SMMU, GPUCC and the GPU register window sit behind clocks and power domains Darwin has no driver
// for. Reading a block whose clock or rail is off can hang the bus instead of failing, so each stage runs only if the previous
// one showed its prerequisite on.
#ifndef ZETA_GPU_POWER_BOARD_H
#define ZETA_GPU_POWER_BOARD_H
#include <stdint.h>

// Stock DT: qcom,lahaina-gcc reg 0x100000 0x1f0000, qcom,lahaina-gpucc reg 0x3d90000 0x9000, kgsl-smmu (qcom,qsmmu-v500,
// qcom,skip-init) reg 0x3da0000 0x20000, qcom,kgsl-3d0 reg 0x3d00000 0x40000.
#define GPB_GCC_GPU_PAGE 0x00171000ULL    // GCC + 0x71000: the GPU branches
#define GPB_GCC_VOTE_PAGE 0x00152000ULL   // GCC + 0x52000: the branch vote register
#define GPB_GPUCC_BASE 0x03d90000ULL
#define GPB_GPUCC_SIZE 0x9000ULL
#define GPB_SMMU_BASE 0x03da0000ULL
#define GPB_SMMU_GR0_SIZE 0x1000ULL       // global space 0 only
#define GPB_GPU_BASE 0x03d00000ULL
#define GPB_GPU_WINDOW 0x1000ULL          // one page is enough for RBBM_STATUS

// gcc-lahaina.ko clk_branch structs (hwcg_reg +0, halt_reg +4, clkr.enable_reg +0x38, enable_mask +0x3c): gcc_gpu_cfg_ahb_clk
// 0x71004, gcc_gpu_memnoc_gfx_clk 0x7100c, gcc_gpu_snoc_dvm_gfx_clk 0x71018, gcc_ddrss_gpu_axi_clk 0x71154; gcc_gpu_gpll0_clk_src
// and gcc_gpu_gpll0_div_clk_src vote 0x52000 bits 15 and 16. Offsets below are relative to the mapped page.
#define GPB_GCC_GPU_CFG_AHB 0x004
#define GPB_GCC_GPU_MEMNOC_GFX 0x00c
#define GPB_GCC_GPU_SNOC_DVM_GFX 0x018
#define GPB_GCC_DDRSS_GPU_AXI 0x154
#define GPB_GCC_PLL_VOTE 0x000
#define GPB_CBCR_CLK_OFF (1u << 31)       // a running branch reads 0
#define GPB_CBCR_ENABLE (1u << 0)

// gpucc-lahaina.ko clk_branch enable registers (mask 1 each): gpu_cc_ahb_clk 0x1078, gpu_cc_cx_gmu_clk 0x1098,
// gpu_cc_hlos1_vote_gpu_smmu_clk 0x5000. Stock DT GDSC regulators: gpu_cc_cx_gdsc 0x3d9106c with hw-ctrl-addr 0x3d91540,
// qcom,clk-dis-wait-val 8, qcom,gds-timeout 500, qcom,retain-regs; gpu_cc_gx_gdsc 0x3d9100c (domain-addr 0x3d9158c, sw-reset
// 0x3d91008), which the GMU owns.
#define GPB_CC_CX_GDSCR 0x106c
#define GPB_CC_GX_GDSCR 0x100c
#define GPB_CC_AHB_CLK 0x1078
#define GPB_CC_CX_GMU_CLK 0x1098
#define GPB_CC_SMMU_VOTE_CLK 0x5000
#define GPB_CC_CX_GDS_HW_CTRL 0x1540
// clk-qcom.ko gdsc-regulator gdsc_probe / gdsc_enable (the qcom,gdsc driver): probe clears HW_CONTROL and SW_OVERRIDE and sets
// CLK_DIS_WAIT 15:12; enable clears SW_COLLAPSE, polls PWR_ON (bit 31) of hw-ctrl-addr 1 us apart for gds-timeout tries and,
// with qcom,retain-regs, then sets RETAIN_FF_ENABLE.
#define GPB_GDSC_SW_COLLAPSE (1u << 0)
#define GPB_GDSC_HW_CONTROL (1u << 1)
#define GPB_GDSC_SW_OVERRIDE (1u << 2)
#define GPB_GDSC_RETAIN_FF (1u << 11)
#define GPB_GDSC_CLK_DIS_WAIT_SHIFT 12
#define GPB_GDSC_CLK_DIS_WAIT_MASK (0xfu << 12)
#define GPB_CX_CLK_DIS_WAIT 8
#define GPB_GDSC_POLL_US 500
#define GPB_GDSC_PWR_ON (1u << 31)

// ARM SMMUv2 global space 0 (IHI 0062D.c): sCR0 0x0, ID0 0x20, ID1 0x24, ID2 0x28, sGFSR 0x48.
#define GPB_SMMU_SCR0 0x0
#define GPB_SMMU_ID0 0x20
#define GPB_SMMU_ID1 0x24
#define GPB_SMMU_ID2 0x28
#define GPB_SMMU_GFSR 0x48
#define GPB_SMMU_SMR(n) (0x800 + 4 * (n))
#define GPB_SMMU_S2CR(n) (0xc00 + 4 * (n))
#define GPB_SMMU_MAX_SMR 128

// a6xx.xml: RBBM_STATUS dword offset 0x0210.
#define GPB_RBBM_STATUS_BYTES (0x0210 * 4)

enum gpb_state {GPB_NOT_RUN = 0, GPB_DONE = 1, GPB_SKIPPED_PREREQ = 2, GPB_SKIPPED_MODE = 3, GPB_NOMAP = 4};

struct gpb_io {
    void *cookie;
    int (*read32)(void *cookie, unsigned window, uint32_t offset, uint32_t *out);   // 0 on success
    int (*write32)(void *cookie, unsigned window, uint32_t offset, uint32_t value);
    void (*delay_us)(void *cookie, unsigned us);                                     // may be NULL
};
enum {GPB_WIN_GCC_GPU = 0, GPB_WIN_GCC_VOTE = 1, GPB_WIN_GPUCC = 2, GPB_WIN_SMMU = 3, GPB_WIN_GPU = 4};

struct gpb_result {
    unsigned mode;                       // 1 read-only; 2 also enable gcc_gpu_cfg_ahb_clk if it is off; 3 also power CX
    enum gpb_state gcc, cc, smmu, gpu;
    uint32_t cfg_ahb, cfg_ahb_after, memnoc, dvm, pll_vote;
    uint32_t cx_gdscr, gx_gdscr, cc_ahb, cc_smmu, cc_gmu;
    uint32_t scr0, id0, id1, id2, gfsr;
    uint32_t smr_valid, smr_first, smr_first_val, s2cr_first_val;
    uint32_t rbbm_status;
    uint32_t cx_before, cx_hwctrl, cc_smmu_before;   // mode 3: GDSCR before, the polled hw-ctrl word, smmu clock before
    unsigned cx_polls;                               // mode 3: hw-ctrl reads until PWR_ON
    unsigned powered_cx, powered_clocks;             // mode 3 actions taken (1 = ran and the status confirmed)
    unsigned enabled_ahb;                            // 1 if mode 2 wrote the enable bit
    int io_error;
};

static inline int gpb_clock_on(uint32_t cbcr) {return (cbcr & GPB_CBCR_CLK_OFF) == 0;}
// sheng: a hardware-gated branch (gcc_gpu_cfg_ahb_clk has hwcg) reads CLK_OFF while idle, so its enable bit is the test.
static inline int gpb_cfg_ahb_enabled(uint32_t cbcr) {return (cbcr & GPB_CBCR_ENABLE) != 0;}
static inline int gpb_gdsc_on(uint32_t gdscr) {return (gdscr & GPB_GDSC_PWR_ON) != 0;}
static inline unsigned gpb_smmu_num_smr(uint32_t id0) {return id0 & 0xff;}        // IDR0.NUMSMRG

static inline int gpb_rd(const struct gpb_io *io, struct gpb_result *r, unsigned window, uint32_t offset, uint32_t *out) {
    uint32_t v = 0;
    if (io->read32(io->cookie, window, offset, &v)) {r->io_error = 1; *out = 0; return -1;}
    *out = v;
    return 0;
}

// The stock gdsc_probe configuration and gdsc_enable for gpu_cc_cx_gdsc; 0 when hw-ctrl reported PWR_ON.
static inline int gpb_cx_enable(const struct gpb_io *io, struct gpb_result *r) {
    uint32_t v = 0, st = 0;
    if (gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GDSCR, &v)) return -1;
    v &= ~(GPB_GDSC_HW_CONTROL | GPB_GDSC_SW_OVERRIDE | GPB_GDSC_CLK_DIS_WAIT_MASK);
    v |= GPB_CX_CLK_DIS_WAIT << GPB_GDSC_CLK_DIS_WAIT_SHIFT;
    if (io->write32(io->cookie, GPB_WIN_GPUCC, GPB_CC_CX_GDSCR, v)) return -1;
    if (io->write32(io->cookie, GPB_WIN_GPUCC, GPB_CC_CX_GDSCR, v & ~GPB_GDSC_SW_COLLAPSE)) return -1;
    if (io->delay_us) io->delay_us(io->cookie, 1);
    for (unsigned i = 0; i < GPB_GDSC_POLL_US; ++i) {
        ++r->cx_polls;
        if (gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GDS_HW_CTRL, &st)) return -1;
        if (gpb_gdsc_on(st)) break;
        if (io->delay_us) io->delay_us(io->cookie, 1);
    }
    r->cx_hwctrl = st;
    if (!gpb_gdsc_on(st)) return 1;
    if (gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GDSCR, &v)) return -1;
    if (!(v & GPB_GDSC_RETAIN_FF) && io->write32(io->cookie, GPB_WIN_GPUCC, GPB_CC_CX_GDSCR, v | GPB_GDSC_RETAIN_FF)) return -1;
    if (io->delay_us) io->delay_us(io->cookie, 2);
    return 0;
}

// Runs the gated sequence. `have` is a bitmask of mapped windows (1 << GPB_WIN_*); a missing window makes its stage GPB_NOMAP.
static inline void gpb_run(const struct gpb_io *io, unsigned mode, unsigned have, struct gpb_result *r) {
    __builtin_memset(r, 0, sizeof *r);
    r->mode = mode;
    if (!mode || !(have & (1u << GPB_WIN_GCC_GPU))) {r->gcc = (mode ? GPB_NOMAP : GPB_SKIPPED_MODE); return;}
    // Stage 1: GCC.
    if (gpb_rd(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_CFG_AHB, &r->cfg_ahb)) return;
    gpb_rd(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_MEMNOC_GFX, &r->memnoc);
    gpb_rd(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_SNOC_DVM_GFX, &r->dvm);
    if (have & (1u << GPB_WIN_GCC_VOTE)) gpb_rd(io, r, GPB_WIN_GCC_VOTE, GPB_GCC_PLL_VOTE, &r->pll_vote);
    r->cfg_ahb_after = r->cfg_ahb;
    if (!gpb_cfg_ahb_enabled(r->cfg_ahb) && mode >= 2) {
        if (!io->write32(io->cookie, GPB_WIN_GCC_GPU, GPB_GCC_GPU_CFG_AHB, r->cfg_ahb | GPB_CBCR_ENABLE)) {
            r->enabled_ahb = 1;
            gpb_rd(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_CFG_AHB, &r->cfg_ahb_after);
        } else r->io_error = 1;
    }
    r->gcc = GPB_DONE;
    // Stage 2: GPUCC needs gcc_gpu_cfg_ahb_clk enabled.
    if (!(have & (1u << GPB_WIN_GPUCC))) r->cc = GPB_NOMAP;
    else if (!gpb_cfg_ahb_enabled(r->cfg_ahb_after)) r->cc = GPB_SKIPPED_PREREQ;
    else {
        gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GDSCR, &r->cx_gdscr);
        gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_GX_GDSCR, &r->gx_gdscr);
        gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_AHB_CLK, &r->cc_ahb);
        gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_SMMU_VOTE_CLK, &r->cc_smmu);
        gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GMU_CLK, &r->cc_gmu);
        r->cc = GPB_DONE;
    }
    // Mode 3: power CX if it is off, then the gpu_cc_ahb_clk and gpu_cc_hlos1_vote_gpu_smmu_clk enables the GPU SMMU needs (the
    // stock kgsl node's clocks). GX is never touched here (the GMU owns it).
    r->cx_before = r->cx_gdscr; r->cc_smmu_before = r->cc_smmu;
    if (mode >= 3 && r->cc == GPB_DONE) {
        if (!gpb_gdsc_on(r->cx_gdscr)) {
            const int e = gpb_cx_enable(io, r);
            if (e < 0) r->io_error = 1;
            gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GDSCR, &r->cx_gdscr);
            r->powered_cx = e == 0;
        }
        if (gpb_gdsc_on(r->cx_gdscr) && !(gpb_clock_on(r->cc_ahb) && gpb_clock_on(r->cc_smmu))) {
            uint32_t a = 0, c = 0;
            int bad = gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_AHB_CLK, &a) | gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_SMMU_VOTE_CLK, &c);
            if (!bad) bad |= io->write32(io->cookie, GPB_WIN_GPUCC, GPB_CC_AHB_CLK, a | GPB_CBCR_ENABLE);
            if (!bad) bad |= io->write32(io->cookie, GPB_WIN_GPUCC, GPB_CC_SMMU_VOTE_CLK, c | GPB_CBCR_ENABLE);
            for (unsigned waited = 0; !bad; waited += 10) {
                if (gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_SMMU_VOTE_CLK, &r->cc_smmu)) {bad = 1; break;}
                if (gpb_clock_on(r->cc_smmu) || waited >= 500) break;
                if (io->delay_us) io->delay_us(io->cookie, 10);
            }
            gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_AHB_CLK, &r->cc_ahb);
            r->powered_clocks = !bad && gpb_clock_on(r->cc_smmu);
            if (bad) r->io_error = 1;
        }
    }
    // Stage 3: the GPU SMMU global space needs CX and its HLOS vote clock.
    if (!(have & (1u << GPB_WIN_SMMU))) r->smmu = GPB_NOMAP;
    else if (r->cc != GPB_DONE || !gpb_gdsc_on(r->cx_gdscr) || !gpb_clock_on(r->cc_smmu)) r->smmu = GPB_SKIPPED_PREREQ;
    else {
        gpb_rd(io, r, GPB_WIN_SMMU, GPB_SMMU_SCR0, &r->scr0);
        gpb_rd(io, r, GPB_WIN_SMMU, GPB_SMMU_ID0, &r->id0);
        gpb_rd(io, r, GPB_WIN_SMMU, GPB_SMMU_ID1, &r->id1);
        gpb_rd(io, r, GPB_WIN_SMMU, GPB_SMMU_ID2, &r->id2);
        gpb_rd(io, r, GPB_WIN_SMMU, GPB_SMMU_GFSR, &r->gfsr);
        unsigned n = gpb_smmu_num_smr(r->id0);
        if (n > GPB_SMMU_MAX_SMR) n = GPB_SMMU_MAX_SMR;
        r->smr_first = 0xffffffffu;
        for (unsigned i = 0; i < n; ++i) {
            uint32_t smr = 0;
            if (gpb_rd(io, r, GPB_WIN_SMMU, GPB_SMMU_SMR(i), &smr)) break;
            if (smr & (1u << 31)) {                      // SMR.VALID
                ++r->smr_valid;
                if (r->smr_first == 0xffffffffu) {
                    r->smr_first = i; r->smr_first_val = smr;
                    gpb_rd(io, r, GPB_WIN_SMMU, GPB_SMMU_S2CR(i), &r->s2cr_first_val);
                }
            }
        }
        r->smmu = GPB_DONE;
    }
    // Stage 4: the GPU register window needs CX and GX on.
    if (!(have & (1u << GPB_WIN_GPU))) r->gpu = GPB_NOMAP;
    else if (r->cc != GPB_DONE || !gpb_gdsc_on(r->cx_gdscr) || !gpb_gdsc_on(r->gx_gdscr)) r->gpu = GPB_SKIPPED_PREREQ;
    else {
        gpb_rd(io, r, GPB_WIN_GPU, GPB_RBBM_STATUS_BYTES, &r->rbbm_status);
        r->gpu = GPB_DONE;
    }
}

static inline const char *gpb_state_text(enum gpb_state s) {
    return s == GPB_DONE ? "ok" : s == GPB_SKIPPED_PREREQ ? "skip" : s == GPB_SKIPPED_MODE ? "off" : s == GPB_NOMAP ? "nomap" : "-";
}
#endif
