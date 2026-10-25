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

// Mode 5/6: the GMU clocks of the stock GMU node (clock-names gmu_clk cxo_clk axi_clk memnoc_clk ahb_clk hub_clk:
// gpu_cc_cx_gmu, gpu_cc_cxo, gcc_ddrss_gpu_axi, gcc_gpu_memnoc_gfx, gpu_cc_ahb, gpu_cc_hub_cx_int), plus the kgsl-3d0 node's
// gcc_gpu_snoc_dvm_gfx and gpu_cc_hub_aon. gpucc-lahaina.ko: lucid_5lpe PLL0 at 0x0 and PLL1 at 0x100 (MODE 0x0, L 0x04,
// CAL_L 0x08, USER_CTL 0x0c, USER_CTL_U 0x10, CONFIG_CTL 0x18/0x1c/0x20, TEST_CTL_U1 0x2c, OPMODE 0x38, ALPHA 0x40);
// gpu_cc_gmu_clk_src cmd_rcgr 0x1120 and gpu_cc_hub_clk_src 0x117c (hid 5 bits, HW_CLK_CTRL_MODE, enable_safe_config).
#define GPB_CC_PLL0 0x0000
#define GPB_CC_PLL1 0x0100
#define GPB_PLL_MODE 0x00
#define GPB_PLL_L_VAL 0x04
#define GPB_PLL_CAL_L_VAL 0x08
#define GPB_PLL_USER_CTL 0x0c
#define GPB_PLL_USER_CTL_U 0x10
#define GPB_PLL_CONFIG_CTL 0x18
#define GPB_PLL_CONFIG_CTL_U 0x1c
#define GPB_PLL_CONFIG_CTL_U1 0x20
#define GPB_PLL_TEST_CTL_U1 0x2c
#define GPB_PLL_OPMODE 0x38
#define GPB_PLL_ALPHA_VAL 0x40
#define GPB_PLL_OUTCTRL (1u << 0)
#define GPB_PLL_RESET_N (1u << 2)
#define GPB_PLL_RUN 1u
#define GPB_CC_GMU_RCGR 0x1120
#define GPB_CC_HUB_RCGR 0x117c
#define GPB_RCG_UPDATE (1u << 0)
#define GPB_RCG_ROOT_EN (1u << 1)
#define GPB_RCG_ROOT_OFF (1u << 31)
#define GPB_RCG_CFG_MASK (0x1fu | (7u << 8) | (3u << 12) | (1u << 20))   // hid, SRC_SEL, MODE, HW_CLK_CTRL
#define GPB_RCG_HW_CLK_CTRL (1u << 20)
// ftbl_gpu_cc_gmu_clk_src F(200000000, P_GPLL0_OUT_MAIN_DIV, 1.5) on parent_map_0 (cfg 6): GMU_FREQUENCY. ftbl_gpu_cc_hub_clk_src
// F(150000000, P_GPLL0_OUT_MAIN_DIV, 2) on parent_map_1 (cfg 6): a6xx_gmu_enable_clks' hub rate. F() stores 2 * div - 1.
#define GPB_GMU_CFG (GPB_RCG_HW_CLK_CTRL | 6u << 8 | 2u)
#define GPB_HUB_CFG (GPB_RCG_HW_CLK_CTRL | 6u << 8 | 3u)
#define GPB_CC_CXO_AON_CLK 0x1004
#define GPB_CC_CXO_CLK 0x109c
#define GPB_CC_HUB_AON_CLK 0x1178
#define GPB_CC_HUB_CX_INT_CLK 0x1204
#define GPB_GPLL0_VOTES ((1u << 15) | (1u << 16))   // gcc_gpu_gpll0_clk_src, gcc_gpu_gpll0_div_clk_src

struct gpb_gmu_clocks {
    uint32_t pll0_mode, pll0_opmode, pll1_mode, pll1_opmode, pll1_l, pll1_cal_l;
    uint32_t gmu_cmd, gmu_cfg, hub_cmd, hub_cfg;
    uint32_t cx_gmu, cxo, hub_cx_int, hub_aon, axi, memnoc, dvm, gpll0_vote;
    int done;                            // 0: GPUCC was not readable, nothing was read
};
// A branch digit: bit 0 enable, bit 1 CLK_OFF.
static inline unsigned gpb_branch_digit(uint32_t cbcr) {return (cbcr & GPB_CBCR_ENABLE) | ((cbcr >> 30) & 2);}
// The GMU registers are read only with CX on and both gpu_cc_ahb_clk and gpu_cc_cx_gmu_clk running.
static inline int gpb_gmu_regs_readable(const struct gpb_result *r, const struct gpb_gmu_clocks *k) {
    return k->done && gpb_gdsc_on(r->cx_gdscr) && gpb_clock_on(r->cc_ahb) && gpb_clock_on(k->cx_gmu);
}
static inline void gpb_read_gmu_clocks(const struct gpb_io *io, struct gpb_result *r, struct gpb_gmu_clocks *k) {
    __builtin_memset(k, 0, sizeof *k);
    if (r->cc != GPB_DONE || !gpb_cfg_ahb_enabled(r->cfg_ahb_after)) return;
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_PLL0 + GPB_PLL_MODE, &k->pll0_mode);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_PLL0 + GPB_PLL_OPMODE, &k->pll0_opmode);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_PLL1 + GPB_PLL_MODE, &k->pll1_mode);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_PLL1 + GPB_PLL_OPMODE, &k->pll1_opmode);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_PLL1 + GPB_PLL_L_VAL, &k->pll1_l);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_PLL1 + GPB_PLL_CAL_L_VAL, &k->pll1_cal_l);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_GMU_RCGR, &k->gmu_cmd);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_GMU_RCGR + 4, &k->gmu_cfg);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_HUB_RCGR, &k->hub_cmd);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_HUB_RCGR + 4, &k->hub_cfg);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GMU_CLK, &k->cx_gmu);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CXO_CLK, &k->cxo);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_HUB_CX_INT_CLK, &k->hub_cx_int);
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_HUB_AON_CLK, &k->hub_aon);
    gpb_rd(io, r, GPB_WIN_GCC_GPU, GPB_GCC_DDRSS_GPU_AXI, &k->axi);
    gpb_rd(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_MEMNOC_GFX, &k->memnoc);
    gpb_rd(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_SNOC_DVM_GFX, &k->dvm);
    gpb_rd(io, r, GPB_WIN_GCC_VOTE, GPB_GCC_PLL_VOTE, &k->gpll0_vote);
    k->done = 1;
}

// Mode 6, in stock order:
//   1 the GPLL0 GPU branch votes (gcc_gpu_gpll0_clk_src / _div_clk_src, 0x52000 bits 15/16)
//   2 gpu_cc_lahaina_probe: clk_lucid_5lpe_pll_configure of PLL0 and PLL1 (skipped for a PLL that runs: OPMODE RUN and OUTCTRL);
//     the PLLs are left in standby, as there. The GMU runs from GPLL0 at its stock 200 MHz, so no PLL is enabled.
//   3 hub_clk 150 MHz and 4 gmu_clk 200 MHz: clk_rcg2_enable with enable_safe_config (force ROOT_EN, wait ROOT_OFF clear,
//     CFG, CMD_UPDATE until it clears within 500 us, drop ROOT_EN)
//   5 clk_bulk_prepare_enable of the GMU node's branches and the kgsl-3d0 node's, waiting for cx_gmu CLK_OFF to clear
struct gpb_gmu_clock_on {
    unsigned step;                       // last step started (1..5), 6 when all passed
    int failed;                          // 1 timeout or refusal at `step`, 2 I/O error
    unsigned hub_polls, gmu_polls, configured;   // configured: bit 0 PLL0, bit 1 PLL1
    uint32_t hub_cfg, gmu_cfg, cx_gmu, pll1_mode;
};
static inline int gpb_pll_running(uint32_t mode, uint32_t opmode) {return (opmode & GPB_PLL_RUN) && (mode & GPB_PLL_OUTCTRL);}
// gpu_cc_pll0_config / gpu_cc_pll1_config; clk_lucid_5lpe_pll_configure skips zero fields except CAL_L.
static inline int gpb_pll_configure(const struct gpb_io *io, struct gpb_result *r, uint32_t base, uint32_t l, uint32_t alpha) {
    static const uint32_t off[] = {GPB_PLL_L_VAL, GPB_PLL_CAL_L_VAL, GPB_PLL_ALPHA_VAL, GPB_PLL_CONFIG_CTL, GPB_PLL_CONFIG_CTL_U,
                                   GPB_PLL_CONFIG_CTL_U1, GPB_PLL_USER_CTL_U, GPB_PLL_TEST_CTL_U1};
    const uint32_t val[] = {l, 0x44, alpha, 0x20485699u, 0x00002261u, 0x2a9a699cu, 0x00000805u, 0x01800000u};
    uint32_t mode = 0;
    for (unsigned i = 0; i < sizeof off / sizeof off[0]; ++i)
        if (io->write32(io->cookie, GPB_WIN_GPUCC, base + off[i], val[i])) return -1;
    if (gpb_rd(io, r, GPB_WIN_GPUCC, base + GPB_PLL_MODE, &mode)) return -1;
    if (io->write32(io->cookie, GPB_WIN_GPUCC, base + GPB_PLL_MODE, mode & ~GPB_PLL_OUTCTRL)) return -1;
    if (io->write32(io->cookie, GPB_WIN_GPUCC, base + GPB_PLL_OPMODE, 0)) return -1;      // PLL_OPMODE_STANDBY
    if (gpb_rd(io, r, GPB_WIN_GPUCC, base + GPB_PLL_MODE, &mode)) return -1;
    return io->write32(io->cookie, GPB_WIN_GPUCC, base + GPB_PLL_MODE, mode | GPB_PLL_RESET_N);
}
// 0 done, 1 timeout, -1 I/O.
static inline int gpb_rcg_set(const struct gpb_io *io, struct gpb_result *r, uint32_t rcgr, uint32_t cfg_value,
                              uint32_t *cfg_after, unsigned *polls) {
    uint32_t cmd = 0, cfg = 0;
    int timeout = 1;
    if (gpb_rd(io, r, GPB_WIN_GPUCC, rcgr, &cmd) || io->write32(io->cookie, GPB_WIN_GPUCC, rcgr, cmd | GPB_RCG_ROOT_EN)) return -1;
    for (unsigned i = 0; i < 500; ++i) {
        if (gpb_rd(io, r, GPB_WIN_GPUCC, rcgr, &cmd)) return -1;
        if (!(cmd & GPB_RCG_ROOT_OFF)) {timeout = 0; break;}
        if (io->delay_us) io->delay_us(io->cookie, 1);
    }
    if (timeout) return 1;
    if (gpb_rd(io, r, GPB_WIN_GPUCC, rcgr + 4, &cfg) ||
        io->write32(io->cookie, GPB_WIN_GPUCC, rcgr + 4, (cfg & ~GPB_RCG_CFG_MASK) | cfg_value)) return -1;
    if (gpb_rd(io, r, GPB_WIN_GPUCC, rcgr, &cmd) || io->write32(io->cookie, GPB_WIN_GPUCC, rcgr, cmd | GPB_RCG_UPDATE)) return -1;
    timeout = 1;
    for (unsigned i = 0; i < 500; ++i) {
        ++*polls;
        if (gpb_rd(io, r, GPB_WIN_GPUCC, rcgr, &cmd)) return -1;
        if (!(cmd & GPB_RCG_UPDATE)) {timeout = 0; break;}
        if (io->delay_us) io->delay_us(io->cookie, 1);
    }
    if (timeout) return 1;
    if (io->write32(io->cookie, GPB_WIN_GPUCC, rcgr, cmd & ~GPB_RCG_ROOT_EN)) return -1;
    return gpb_rd(io, r, GPB_WIN_GPUCC, rcgr + 4, cfg_after) ? -1 : 0;
}
static inline int gpb_set_bit0(const struct gpb_io *io, struct gpb_result *r, unsigned w, uint32_t off) {
    uint32_t v = 0;
    if (gpb_rd(io, r, w, off, &v)) return -1;
    return (v & GPB_CBCR_ENABLE) ? 0 : io->write32(io->cookie, w, off, v | GPB_CBCR_ENABLE);
}
static inline void gpb_gmu_clocks_on(const struct gpb_io *io, struct gpb_result *r, const struct gpb_gmu_clocks *k,
                                     struct gpb_gmu_clock_on *o) {
    __builtin_memset(o, 0, sizeof *o);
    int e = 0;
    uint32_t v = 0;
    o->step = 1;
    if (!k->done || !gpb_gdsc_on(r->cx_gdscr)) {o->failed = 1; return;}
    if (gpb_rd(io, r, GPB_WIN_GCC_VOTE, GPB_GCC_PLL_VOTE, &v)) goto io;
    if ((v & GPB_GPLL0_VOTES) != GPB_GPLL0_VOTES) {
        if (io->write32(io->cookie, GPB_WIN_GCC_VOTE, GPB_GCC_PLL_VOTE, v | GPB_GPLL0_VOTES)) goto io;
        if (io->delay_us) io->delay_us(io->cookie, 10);   // BRANCH_HALT_DELAY
    }
    o->step = 2;
    if (!gpb_pll_running(k->pll0_mode, k->pll0_opmode)) {
        if (gpb_pll_configure(io, r, GPB_CC_PLL0, 0x18, 0x6000)) goto io;
        o->configured |= 1;
    }
    if (!gpb_pll_running(k->pll1_mode, k->pll1_opmode)) {
        if (gpb_pll_configure(io, r, GPB_CC_PLL1, 0x1a, 0xaaa)) goto io;
        o->configured |= 2;
    }
    o->step = 3;
    e = gpb_rcg_set(io, r, GPB_CC_HUB_RCGR, GPB_HUB_CFG, &o->hub_cfg, &o->hub_polls);
    if (e) {o->failed = e < 0 ? 2 : 1; goto out;}
    o->step = 4;
    e = gpb_rcg_set(io, r, GPB_CC_GMU_RCGR, GPB_GMU_CFG, &o->gmu_cfg, &o->gmu_polls);
    if (e) {o->failed = e < 0 ? 2 : 1; goto out;}
    o->step = 5;
    if (gpb_set_bit0(io, r, GPB_WIN_GPUCC, GPB_CC_CXO_AON_CLK) || gpb_set_bit0(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GMU_CLK) ||
        gpb_set_bit0(io, r, GPB_WIN_GPUCC, GPB_CC_CXO_CLK) || gpb_set_bit0(io, r, GPB_WIN_GCC_GPU, GPB_GCC_DDRSS_GPU_AXI) ||
        gpb_set_bit0(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_MEMNOC_GFX) || gpb_set_bit0(io, r, GPB_WIN_GPUCC, GPB_CC_AHB_CLK) ||
        gpb_set_bit0(io, r, GPB_WIN_GPUCC, GPB_CC_HUB_CX_INT_CLK) || gpb_set_bit0(io, r, GPB_WIN_GCC_GPU, GPB_GCC_GPU_SNOC_DVM_GFX) ||
        gpb_set_bit0(io, r, GPB_WIN_GPUCC, GPB_CC_HUB_AON_CLK)) goto io;
    e = 1;
    for (unsigned i = 0; i < 500; ++i) {
        if (gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_CX_GMU_CLK, &o->cx_gmu)) goto io;
        if (gpb_clock_on(o->cx_gmu)) {e = 0; break;}
        if (io->delay_us) io->delay_us(io->cookie, 1);
    }
    if (e) {o->failed = 1; goto out;}
    o->step = 6;
    goto out;
io:
    o->failed = 2;
out:
    gpb_rd(io, r, GPB_WIN_GPUCC, GPB_CC_PLL1 + GPB_PLL_MODE, &o->pll1_mode);
}

static inline const char *gpb_state_text(enum gpb_state s) {
    return s == GPB_DONE ? "ok" : s == GPB_SKIPPED_PREREQ ? "skip" : s == GPB_SKIPPED_MODE ? "off" : s == GPB_NOMAP ? "nomap" : "-";
}
#endif
