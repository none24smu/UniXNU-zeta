/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* sheng package/ShengGmu.c, with the stock A660 sequence of msm_kgsl.ko's adreno_a6xx_gmu.c (see ZetaGmu.h). Register
 * dword offsets are the stock a6xx_reg.h ones; the GMU window starts at GPU dword 0x1a800 (0x3d6a000 - 0x3d00000). */
#include "ZetaGmu.h"
#include "AdrenoFirmware.h"
#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error zeta GMU requires little-endian AArch64
#endif

const uint64_t zeta_gmu_window_physical[ZetaGmuWindows] = {0x03d6a000, 0x03de0000, 0x0b290000, 0x03d00000};
const size_t zeta_gmu_window_bytes[ZetaGmuWindows] = {0x34000, 0x10000, 0x10000, 0x40000};

/* a6xx_reg.h (GPU dword offsets). */
#define GMU_CM3_ITCM_START 0x1b400u
#define GMU_CM3_DTCM_START 0x1c400u
#define GMU_CM3_SYSRESET 0x1f800u
#define GMU_CM3_BOOT_CONFIG 0x1f801u
#define GMU_CM3_FW_INIT_RESULT 0x1f81cu
#define GMU_CM3_CFG 0x1f82du
#define GMU_ICACHE_CONFIG 0x1f400u
#define GMU_DCACHE_CONFIG 0x1f401u
#define GMU_SYS_BUS_CONFIG 0x1f40fu
#define GMU_PWR_COL_INTER_FRAME_CTRL 0x1f8c0u
#define GMU_RPMH_CTRL 0x1f8e8u
#define GMU_CX_FAL_INTF 0x1f8f0u
#define GMU_CX_FALNEXT_INTF 0x1f8f1u
#define GMU_PWR_COL_CP_MSG 0x1f900u
#define GMU_PWR_COL_CP_RESP 0x1f901u
#define GMU_HFI_CTRL_STATUS 0x1f980u
#define GMU_HFI_SFR_ADDR 0x1f982u
#define GMU_HFI_QTBL_INFO 0x1f984u
#define GMU_HFI_QTBL_ADDR 0x1f985u
#define GMU_HFI_CTRL_INIT 0x1f986u
#define GMU_GMU2HOST_INTR_CLR 0x1f991u
#define GMU_GMU2HOST_INTR_INFO 0x1f992u
#define GMU_GMU2HOST_INTR_MASK 0x1f993u
#define GMU_HOST2GMU_INTR_SET 0x1f994u
#define GMU_GENERAL_7 0x1f9ccu
#define GMU_AO_HOST_INTERRUPT_CLR 0x23b04u
#define GMU_AO_HOST_INTERRUPT_STATUS 0x23b05u
#define GMU_AO_HOST_INTERRUPT_MASK 0x23b06u
#define GMU_AHB_FENCE_RANGE_0 0x23b11u
#define GPU_GBIF_HALT 0x3c45u
/* RSCC (a650 family: its own block, dword offsets) and the PDC cfg block. */
#define RSCC_RSC_STATUS0_DRV0 0x004u
#define RSCC_PDC_SEQ_START_ADDR 0x008u
#define RSCC_PDC_MATCH_VALUE_LO 0x009u
#define RSCC_PDC_MATCH_VALUE_HI 0x00au
#define RSCC_PDC_SLAVE_ID_DRV0 0x00bu
#define RSCC_HIDDEN_TCS_CMD0_ADDR 0x00du
#define RSCC_HIDDEN_TCS_CMD0_DATA 0x00eu
#define RSCC_OVERRIDE_START_ADDR 0x100u
#define RSCC_SEQ_BUSY_DRV0 0x101u
#define RSCC_SEQ_MEM_0_DRV0 0x180u
#define PDC_GPU_ENABLE_PDC 0x1140u
#define PDC_GPU_SEQ_START_ADDR 0x1148u

#define GMU_CORE_GPU_DELTA 0x6a000u
/* adreno_a6xx_gmu.c / .h and adreno_a6xx_hfi.h. */
#define FENCE_RANGE_MASK (UINT32_C(1) << 31 | (0xau << 2) << 18 | 0x8a0u)
#define RPMH_ENABLE_MASK 0xf11u                       /* interface, LLC, DDR, MX, CX, GFX votes */
#define AO_INT_MASK 0x29u                             /* WDOG_BITE | FENCE_ERR | HOST_AHB_BUS_ERR */
#define HFI_IRQ_MASK ((1u << 1) | (1u << 2) | (1u << 15))
#define CM3_FAULT (1u << 15)
#define GMU_LOG_BYTES 0x4000u
/* adreno_gpu_core_a660v2 qcom,chipid 0x06060001, compressed as a6xx_gmu_register_config passes it: core and major kept,
 * minor in 15:12, patch in 11:8. */
#define CHIPID_FOR_GMU 0x06060100u
/* sha256 of a660_gmu.bin in the stock vendor_a /firmware (the file itself is never in this repository). */
static const uint8_t firmware_sha256[32] = {
    0x6b, 0xb9, 0x36, 0x0a, 0x16, 0x01, 0x25, 0x3a, 0x86, 0xee, 0x3a, 0xe1, 0xb9, 0xb9, 0x16, 0xf5,
    0xf1, 0x83, 0x2a, 0x72, 0xd5, 0x5e, 0x9b, 0x85, 0x73, 0x56, 0x7f, 0x17, 0x40, 0xc9, 0x4e, 0x2b};
#define FIRMWARE_BYTES 55256u

static int extent(uintptr_t at, size_t bytes) {return at && bytes && bytes - 1 <= UINTPTR_MAX - at;}
static int overlap(uintptr_t a, size_t na, uintptr_t b, size_t nb) {return a <= b ? (b - a < na) : (a - b < nb);}
static size_t core_offset(uint32_t word) {return ((size_t)word << 2) - GMU_CORE_GPU_DELTA;}
static int rd(ZetaGmuDevice *d, unsigned w, size_t at, uint32_t *v, ZetaGmuResult *r)
{++r->read_attempts; return d->io.read32(d->io.cookie, w, at, v);}
static int wr(ZetaGmuDevice *d, unsigned w, size_t at, uint32_t v, ZetaGmuResult *r)
{++r->write_attempts; return d->io.write32(d->io.cookie, w, at, v);}
static int core_rd(ZetaGmuDevice *d, uint32_t word, uint32_t *v, ZetaGmuResult *r)
{return rd(d, ZetaGmuCore, core_offset(word), v, r);}
static int core_wr(ZetaGmuDevice *d, uint32_t word, uint32_t v, ZetaGmuResult *r)
{return wr(d, ZetaGmuCore, core_offset(word), v, r);}
static int rscc_wr(ZetaGmuDevice *d, uint32_t word, uint32_t v, ZetaGmuResult *r)
{return wr(d, ZetaGmuRscc, (size_t)word << 2, v, r);}
static ZetaGmuStatus check_faults(ZetaGmuDevice *d, ZetaGmuResult *r)
{
    if (core_rd(d, GMU_AO_HOST_INTERRUPT_STATUS, &r->ao_fault_status, r) ||
        core_rd(d, GMU_GMU2HOST_INTR_INFO, &r->cm3_fault_status, r)) return ZetaGmuIoError;
    return (r->ao_fault_status & AO_INT_MASK) || (r->cm3_fault_status & CM3_FAULT) ? ZetaGmuFault : ZetaGmuSuccess;
}
static int notify(void *cookie)
{
    ZetaGmuDevice *d = cookie;
    return d->io.barrier(d->io.cookie) ||
           d->io.write32(d->io.cookie, ZetaGmuCore, core_offset(GMU_HOST2GMU_INTR_SET), 1) ||
           d->io.barrier(d->io.cookie);
}
/* timed_poll_check: GMU_START_TIMEOUT 100 ms, here also bounded by the caller's iteration budget. */
static ZetaGmuStatus poll(ZetaGmuDevice *d, uint32_t reg, uint32_t mask, uint32_t expected, unsigned budget,
                          uint32_t *observed, ZetaGmuResult *r)
{
    uint64_t start, last, now;
    if (d->services.now_us(d->services.cookie, &start)) return ZetaGmuClockError;
    last = start;
    for (unsigned i = 0; i < budget; ++i) {
        if (d->services.now_us(d->services.cookie, &now) || now < last) return ZetaGmuClockError;
        if (now - start >= 100000) return ZetaGmuTimeout;
        last = now; ++r->poll_reads;
        ZetaGmuStatus fault = check_faults(d, r);
        if (fault != ZetaGmuSuccess) return fault;
        if (core_rd(d, reg, observed, r)) return ZetaGmuIoError;
        if ((*observed & mask) == expected) return d->io.barrier(d->io.cookie) ? ZetaGmuIoError : ZetaGmuSuccess;
        if (i + 1 < budget && d->services.wait_us(d->services.cookie, 100)) return ZetaGmuClockError;
    }
    return ZetaGmuTimeout;
}
static void reset_after_failure(ZetaGmuDevice *d, ZetaGmuResult *r)
{
    uint32_t actual;
    r->reset_verified = 0; d->poisoned = 1; d->hfi.poisoned = 1;
    if (!core_wr(d, GMU_CM3_SYSRESET, 1, r) && !d->io.barrier(d->io.cookie) && !core_rd(d, GMU_CM3_SYSRESET, &actual, r) &&
        actual == 1) r->reset_verified = 1;
}
static uint32_t le32(const uint8_t *p) {return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;}

static ZetaGmuStatus validate(ZetaGmuDevice *d, const ZetaGmuConfig *c, ZetaGmuResult *r)
{
    if (!d || !c || !d->io.read32 || !d->io.write32 || !d->io.barrier || !d->services.sha256 || !d->services.now_us ||
        !d->services.wait_us || !c->firmware || c->firmware_bytes != FIRMWARE_BYTES ||
        !extent((uintptr_t)c->firmware, c->firmware_bytes) || !c->poll_budget || c->poll_budget > 1024)
        return ZetaGmuArgument;
    if (d->poisoned) return ZetaGmuPoisoned;
    if (d->boot_attempted) return ZetaGmuBusy;
    for (unsigned i = 0; i < ZetaGmuWindows; ++i) if (d->io.bytes[i] != zeta_gmu_window_bytes[i]) return ZetaGmuArgument;
    /* NativeAdrenoGmuContextPayloads: the stock a6xx_gmu_vma cache region (0x4000 + 0xffc000) and the non-cached kernel
     * range from 0x60000000, which holds the firmware's two persistent preallocations (0x60000000, 0x60001000). */
    const ZetaGmuMemory *mem[] = {&c->icache, &c->dummy, &c->debug, &c->log, &c->hfi};
    const size_t sizes[] = {0xffc000, 0x4000, 0x7000, GMU_LOG_BYTES, 0x4000};
    for (unsigned i = 0; i < 5; ++i) {
        const ZetaGmuMemory *m = mem[i];
        if (m->bytes != sizes[i] || !extent((uintptr_t)m->cpu, m->bytes) || ((uintptr_t)m->cpu & 4095) || !m->iova ||
            (m->iova & 4095) || m->iova > UINT32_MAX - (m->bytes - 1) ||
            overlap((uintptr_t)m->cpu, m->bytes, (uintptr_t)c->firmware, c->firmware_bytes)) return ZetaGmuArgument;
        for (unsigned j = 0; j < i; ++j)
            if (overlap((uintptr_t)m->cpu, m->bytes, (uintptr_t)mem[j]->cpu, mem[j]->bytes) ||
                overlap((uintptr_t)m->iova, m->bytes, (uintptr_t)mem[j]->iova, mem[j]->bytes)) return ZetaGmuArgument;
    }
    if (c->icache.iova != 0x4000 || c->dummy.iova != 0x60000000) return ZetaGmuArgument;
    if (d->services.sha256(d->services.cookie, c->firmware, c->firmware_bytes, r->sha256)) return ZetaGmuFirmware;
    for (unsigned i = 0; i < 32; ++i) if (r->sha256[i] != firmware_sha256[i]) return ZetaGmuFirmware;
    r->hash_verified = 1;
    return ZetaGmuSuccess;
}

/* a6xx_gmu_load_fw: ITCM and DTCM through the GMU window (load_tcm), the cache region through its payload. */
static int load_word(ZetaGmuDevice *d, const ZetaGmuConfig *c, const AdrenoFirmwareBlock *b, size_t at, uint32_t word,
                     ZetaGmuResult *r)
{
    if (b->region_identifier == 2) {c->icache.cpu[(b->address - 0x4000 + at) / 4] = word; return 0;}
    const uint32_t reg = b->region_identifier == 1 ? GMU_CM3_ITCM_START + b->address / 4
                                                   : GMU_CM3_DTCM_START + (b->address - 0x10004000) / 4;
    return core_wr(d, reg + (uint32_t)(at / 4), word, r);
}
static int read_word(ZetaGmuDevice *d, const ZetaGmuConfig *c, const AdrenoFirmwareBlock *b, size_t at, uint32_t *word,
                     ZetaGmuResult *r)
{
    if (b->region_identifier == 2) {*word = c->icache.cpu[(b->address - 0x4000 + at) / 4]; return 0;}
    const uint32_t reg = b->region_identifier == 1 ? GMU_CM3_ITCM_START + b->address / 4
                                                   : GMU_CM3_DTCM_START + (b->address - 0x10004000) / 4;
    return core_rd(d, reg + (uint32_t)(at / 4), word, r);
}

static void step(ZetaGmuDevice *d, unsigned phase, unsigned at)
{if (d->services.progress) d->services.progress(d->services.cookie, phase, at);}

static ZetaGmuStatus load_and_start_hfi(ZetaGmuDevice *d, const ZetaGmuConfig *c, ZetaGmuResult *r)
{
    ZetaGmuStatus status = validate(d, c, r);
    if (status != ZetaGmuSuccess) return status;
    const AdrenoFirmwareRegion regions[] = {{0, 0x4000, 1}, {0x4000, 0xffc000, 2}, {0x10004000, 0x4000, 3}};
    AdrenoFirmwareBlock blocks[32];
    size_t count = 0;
    if (AdrenoFirmwarePlanGmu(c->firmware, c->firmware_bytes, regions, 3, blocks, 32, &count) != AdrenoFirmwareSuccess)
        return ZetaGmuFirmware;
    r->blocks = (uint32_t)count;
    r->phase = 1;
    step(d, 1, 0);
    uint32_t value;
    if (core_rd(d, GMU_CM3_SYSRESET, &r->sysreset_before, r) || core_rd(d, GMU_HFI_CTRL_STATUS, &r->hfi_status_before, r) ||
        rd(d, ZetaGmuRscc, RSCC_SEQ_BUSY_DRV0 << 2, &r->rsc_busy_before, r) || core_rd(d, GMU_GENERAL_7, &r->general7_before, r))
        return ZetaGmuIoError;
    if (r->sysreset_before != 1 || r->rsc_busy_before) return ZetaGmuBusy;
    r->reset_verified = 1;
    if (r->hfi_status_before & 1) return ZetaGmuStateMismatch;   /* a stale ready bit cannot pass */
    status = check_faults(d, r);
    if (status != ZetaGmuSuccess) return status;

    r->phase = 2;
    step(d, 2, 0);
    d->boot_attempted = 1;
    /* The payloads are the GMU's own and zero, as dma_alloc_attrs + memset leave them; then the HFI queues. */
    const ZetaGmuMemory *memory[] = {&c->icache, &c->dummy, &c->debug, &c->log};
    for (unsigned m = 0; m < 4; ++m) for (size_t i = 0; i < memory[m]->bytes / 4; ++i) memory[m]->cpu[i] = 0;
    step(d, 2, 1);
    if (AdrenoHfiInitializeStopped(&d->hfi, c->hfi.cpu, c->hfi.bytes, c->hfi.iova, d, notify) != AdrenoHfiSuccess) {
        status = ZetaGmuArgument; goto failed;
    }
    step(d, 2, 2);
    for (size_t i = 0; i < count; ++i) {
        step(d, 2, 0x100 + (unsigned)i);
        for (size_t at = 0; at < blocks[i].bytes; at += 4)
            if (load_word(d, c, blocks + i, at, le32(c->firmware + blocks[i].payload_offset + at), r)) {
                status = ZetaGmuIoError; goto failed;
            }
    }
    if (d->io.barrier(d->io.cookie)) {status = ZetaGmuIoError; goto failed;}
    step(d, 2, 3);
    for (size_t i = 0; i < count; ++i)
        for (size_t at = 0; at < blocks[i].bytes; at += 4) {
            if (read_word(d, c, blocks + i, at, &value, r)) {status = ZetaGmuIoError; goto failed;}
            if (value != le32(c->firmware + blocks[i].payload_offset + at)) {status = ZetaGmuStateMismatch; goto failed;}
        }

    /* a6xx_gmu_register_config. */
    r->phase = 3;
    step(d, 3, 0);
    {
        const uint32_t regs[] = {GMU_CX_FALNEXT_INTF, GMU_CX_FAL_INTF, GMU_GENERAL_7, GMU_CM3_FW_INIT_RESULT,
                                 GMU_CM3_BOOT_CONFIG, GMU_HFI_QTBL_ADDR, GMU_HFI_QTBL_INFO, GMU_AHB_FENCE_RANGE_0, GMU_CM3_CFG};
        const uint32_t values[] = {1, 1, 1, 0, 2, (uint32_t)c->hfi.iova, 1, FENCE_RANGE_MASK, 0x4052};
        for (unsigned i = 0; i < sizeof regs / sizeof regs[0]; ++i)
            if (core_wr(d, regs[i], values[i], r)) {status = ZetaGmuIoError; goto failed;}
        step(d, 3, 1);
        /* GBIF halt may be left asserted by an earlier reset; the GPU block's GBIF is in CX. */
        if (wr(d, ZetaGmuGpu, (size_t)GPU_GBIF_HALT << 2, 0, r)) {status = ZetaGmuIoError; goto failed;}
        step(d, 3, 2);
        const uint32_t regs2[] = {GMU_PWR_COL_CP_RESP, GMU_HFI_SFR_ADDR, GMU_PWR_COL_CP_MSG,
                                  /* a6xx_gmu_power_config, IFPC off */
                                  GMU_SYS_BUS_CONFIG, GMU_ICACHE_CONFIG, GMU_DCACHE_CONFIG, GMU_PWR_COL_INTER_FRAME_CTRL};
        const uint32_t values2[] = {0, CHIPID_FOR_GMU, ((uint32_t)c->log.iova & 0xfffff000u) | ((GMU_LOG_BYTES / 4096 - 1) & 0xff),
                                    1, 1, 1, 0x9c40400};
        for (unsigned i = 0; i < sizeof regs2 / sizeof regs2[0]; ++i)
            if (core_wr(d, regs2[i], values2[i], r)) {status = ZetaGmuIoError; goto failed;}
        step(d, 3, 3);
        if (core_rd(d, GMU_RPMH_CTRL, &value, r) || core_wr(d, GMU_RPMH_CTRL, value | RPMH_ENABLE_MASK, r)) {
            status = ZetaGmuIoError; goto failed;
        }
    }
    /* a6xx_gmu_version_info: fixed DTCM words; then a6xx_gmu_irq_enable's clear and mask (interrupts stay unrouted: this
     * driver polls). */
    step(d, 3, 4);
    if (core_rd(d, GMU_CM3_DTCM_START + 0xff8, &r->core_version, r) || core_rd(d, GMU_CM3_DTCM_START + 0xffc, &r->hfi_version, r) ||
        core_wr(d, GMU_GMU2HOST_INTR_CLR, UINT32_MAX, r) || core_wr(d, GMU_AO_HOST_INTERRUPT_CLR, UINT32_MAX, r) ||
        core_wr(d, GMU_GMU2HOST_INTR_MASK, ~HFI_IRQ_MASK, r) || core_wr(d, GMU_AO_HOST_INTERRUPT_MASK, ~AO_INT_MASK, r) ||
        d->io.barrier(d->io.cookie)) {status = ZetaGmuIoError; goto failed;}
    if ((r->hfi_version >> 28) < 2) {status = ZetaGmuFirmware; goto failed;}   /* the HFI v2 path is the only one here */

    /* a6xx_gmu_device_start. */
    r->phase = 4;
    step(d, 4, 0);
    {
        const uint32_t mask = r->core_version <= UINT32_C(0x20010004) ? UINT32_MAX : 0x1ff;
        const uint32_t ready = mask == UINT32_MAX ? UINT32_C(0xbabeface) : 0x100;
        r->reset_verified = 0;
        if (core_wr(d, GMU_CM3_SYSRESET, 0, r) || d->io.barrier(d->io.cookie)) {status = ZetaGmuIoError; goto failed;}
        for (unsigned at = 0x10; at <= 0x13; ++at) step(d, 4, at);
        status = poll(d, GMU_CM3_FW_INIT_RESULT, mask, ready, c->poll_budget, &r->firmware_init_result, r);
        if (status != ZetaGmuSuccess) goto failed;
        r->firmware_ready = 1;
        step(d, 4, 1);
    }
    /* a6xx_load_pdc_ucode with pdc_in_aop (only the GPU PDC start address and enable), then a6xx_load_rsc_ucode. */
    r->phase = 5;
    step(d, 5, 0);
    if (wr(d, ZetaGmuPdc, (size_t)PDC_GPU_SEQ_START_ADDR << 2, 0, r) ||
        wr(d, ZetaGmuPdc, (size_t)PDC_GPU_ENABLE_PDC << 2, 0x80000001u, r) || d->io.barrier(d->io.cookie)) {
        status = ZetaGmuIoError; goto failed;
    }
    step(d, 5, 1);
    {
        const uint32_t regs[] = {RSCC_RSC_STATUS0_DRV0, RSCC_PDC_SLAVE_ID_DRV0, RSCC_HIDDEN_TCS_CMD0_DATA,
            RSCC_HIDDEN_TCS_CMD0_ADDR, RSCC_HIDDEN_TCS_CMD0_DATA + 2, RSCC_HIDDEN_TCS_CMD0_ADDR + 2,
            RSCC_HIDDEN_TCS_CMD0_DATA + 4, RSCC_HIDDEN_TCS_CMD0_ADDR + 4, RSCC_OVERRIDE_START_ADDR, RSCC_PDC_SEQ_START_ADDR,
            RSCC_PDC_MATCH_VALUE_LO, RSCC_PDC_MATCH_VALUE_HI, RSCC_SEQ_MEM_0_DRV0, RSCC_SEQ_MEM_0_DRV0 + 1,
            RSCC_SEQ_MEM_0_DRV0 + 2, RSCC_SEQ_MEM_0_DRV0 + 3, RSCC_SEQ_MEM_0_DRV0 + 4};
        const uint32_t values[] = {1u << 24, 1, 0, 0, 0, 0, 0x80000000u, 0, 0, 0x4520, 0x4510, 0x4514,
                                   0xeaaae5a0u, 0xe1a1ebabu, 0xa2e0a581u, 0xecac82e2u, 0x0020edadu};
        for (unsigned i = 0; i < sizeof regs / sizeof regs[0]; ++i)
            if (rscc_wr(d, regs[i], values[i], r)) {status = ZetaGmuIoError; goto failed;}
        if (d->io.barrier(d->io.cookie)) {status = ZetaGmuIoError; goto failed;}
    }
    /* a6xx_gmu_hfi_start. */
    r->phase = 6;
    step(d, 6, 0);
    if (core_wr(d, GMU_HFI_CTRL_INIT, 1, r) || d->io.barrier(d->io.cookie)) {status = ZetaGmuIoError; goto failed;}
    status = poll(d, GMU_HFI_CTRL_STATUS, 1, 1, c->poll_budget, &r->hfi_status, r);
    if (status != ZetaGmuSuccess) goto failed;
    status = check_faults(d, r);
    if (status != ZetaGmuSuccess) goto failed;
    r->hfi_ready = 1;
    step(d, 6, 1);
    r->phase = 7;
    return ZetaGmuSuccess;
failed:
    reset_after_failure(d, r);
    return status;
}

typedef struct {ZetaGmuDevice *device; ZetaGmuStartupResult *result;} StartupContext;
static int startup_now(void *cookie, uint64_t *value)
{ZetaGmuDevice *d = ((StartupContext *)cookie)->device; return d->services.now_us(d->services.cookie, value);}
static int startup_wait(void *cookie, unsigned us)
{ZetaGmuDevice *d = ((StartupContext *)cookie)->device; return d->services.wait_us(d->services.cookie, us);}
static int startup_health(void *cookie)
{
    StartupContext *c = cookie;
    ZetaGmuDevice *d = c->device;
    ZetaGmuStartupResult *r = c->result;
    uint32_t reset, status;
    r->health_status = check_faults(d, &r->load);
    if (r->health_status != ZetaGmuSuccess) return 1;
    if (core_rd(d, GMU_CM3_SYSRESET, &reset, &r->load) || core_rd(d, GMU_HFI_CTRL_STATUS, &status, &r->load))
        r->health_status = ZetaGmuIoError;
    else if (reset != 0 || !(status & 1)) r->health_status = ZetaGmuStateMismatch;
    return r->health_status != ZetaGmuSuccess;
}
ZetaGmuStatus ZetaGmuColdStart(ZetaGmuDevice *d, const ZetaGmuConfig *c, const AdrenoHfiStartupConfig *config,
                               const ZetaGmuLimits *limits, ZetaGmuStartupResult *r)
{
    if (!r) return ZetaGmuArgument;
    *r = (ZetaGmuStartupResult){0};
    r->protocol.resources_must_retain = 1;
    r->protocol_status = AdrenoHfiStartupInvalid;   /* not attempted until the load succeeds */
    if (!d || !c || !limits || AdrenoHfiStartupValidate(config) != AdrenoHfiStartupSuccess) return ZetaGmuArgument;
    StartupContext context = {d, r};
    AdrenoHfiStartupServices services = {&context, startup_now, startup_wait, startup_health, limits->polls_per_command,
                                         limits->wait_interval_us, limits->command_timeout_us, limits->total_timeout_us};
    if (AdrenoHfiStartupValidateServices(&services) != AdrenoHfiStartupSuccess) return ZetaGmuArgument;
    if (d->poisoned || d->startup.poisoned) return ZetaGmuPoisoned;
    if (d->startup.attempted || d->startup.completed) return ZetaGmuBusy;
    ZetaGmuStatus status = load_and_start_hfi(d, c, &r->load);
    if (status != ZetaGmuSuccess) return status;
    /* a6xx_hfi_start for HFI v2: perf (DCVS) table, bandwidth table, ACD/LM/BCL off, CORE_FW_START; the kit then sends
     * H2F_MSG_START, which a6xx_gpu_boot sends after the GPU OOB (upstream sends it here too). */
    r->protocol_status = AdrenoHfiStartupRun(&d->startup, &d->hfi, config, &services, &r->protocol);
    if (r->protocol_status == AdrenoHfiStartupSuccess) return ZetaGmuSuccess;
    switch (r->protocol_status) {
    case AdrenoHfiStartupClockError: case AdrenoHfiStartupWaitError: status = ZetaGmuClockError; break;
    case AdrenoHfiStartupTimeout: status = ZetaGmuTimeout; break;
    case AdrenoHfiStartupPlatformFault: status = r->health_status; break;
    default: status = ZetaGmuProtocolError; break;
    }
    reset_after_failure(d, &r->load);
    d->startup.poisoned = 1;
    return status;
}

static int fits(ZetaGmuMmio *m, unsigned window, size_t at)
{
    if (!m || window >= ZetaGmuWindows) return 0;
    ZetaGmuMmioWindow *w = m->windows + window;
    return extent((uintptr_t)w->cpu, w->bytes) && !((uintptr_t)w->cpu & 3) && !(at & 3) && at <= w->bytes && w->bytes - at >= 4;
}
static int mmio_read(void *cookie, unsigned window, size_t at, uint32_t *v)
{ZetaGmuMmio *m = cookie; if (!v || !fits(m, window, at)) return 1; *v = *(volatile uint32_t *)(m->windows[window].cpu + at); return 0;}
static int mmio_write(void *cookie, unsigned window, size_t at, uint32_t v)
{ZetaGmuMmio *m = cookie; if (!fits(m, window, at)) return 1; *(volatile uint32_t *)(m->windows[window].cpu + at) = v; return 0;}
static int mmio_barrier(void *cookie) {(void)cookie; __asm__ volatile("dsb sy" ::: "memory"); return 0;}
ZetaGmuStatus ZetaGmuBindMmio(ZetaGmuMmio *m, ZetaGmuIo *out)
{
    if (!out) return ZetaGmuArgument;
    *out = (ZetaGmuIo){0};
    if (!m) return ZetaGmuArgument;
    for (unsigned i = 0; i < ZetaGmuWindows; ++i) {
        const ZetaGmuMmioWindow *w = m->windows + i;
        if (!fits(m, i, 0) || w->physical != zeta_gmu_window_physical[i] || w->bytes != zeta_gmu_window_bytes[i])
            return ZetaGmuArgument;
        for (unsigned j = 0; j < i; ++j)
            if (overlap((uintptr_t)w->cpu, w->bytes, (uintptr_t)m->windows[j].cpu, m->windows[j].bytes)) return ZetaGmuArgument;
    }
    out->cookie = m; out->read32 = mmio_read; out->write32 = mmio_write; out->barrier = mmio_barrier;
    for (unsigned i = 0; i < ZetaGmuWindows; ++i) out->bytes[i] = m->windows[i].bytes;
    return ZetaGmuSuccess;
}
