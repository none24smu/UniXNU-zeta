/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* zeta's Adreno 660 GMU cold start, sheng package/ShengGmu.h on the stock Surface Duo 2 sequence: msm_kgsl.ko
 * (5.4.233, whose source is the vendor's kernel/msm-5.4 drivers/gpu/msm) a6xx_gmu_first_boot for adreno_gpu_core_a660v2
 * (gmu_major 2, veto_fal10, pdc_in_aop, no SPTPRAC GDSC). The HFI transport and startup messages are UniXNU
 * kits/AdrenoFirmware, the modern A6xx wire format the stock HFI v2 path sends (perf table 58 words, bandwidth table 159,
 * CORE_FW_START). The votes are built here from the stock DT and the AOP command DB the way adreno_a6xx_rpmh.c builds them. */
#ifndef ZETA_GMU_H
#define ZETA_GMU_H
#include "AdrenoHfiStartup.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Windows, from the stock DT: gmu kgsl_gmu_reg 0x3d6a000+0x34000, kgsl-3d0 rscc 0x3de0000+0x10000, gmu kgsl_gmu_pdc_cfg
 * 0xb290000+0x10000, kgsl_3d0_reg_memory 0x3d00000+0x40000. */
enum {ZetaGmuCore, ZetaGmuRscc, ZetaGmuPdc, ZetaGmuGpu, ZetaGmuWindows};
extern const uint64_t zeta_gmu_window_physical[ZetaGmuWindows];
extern const size_t zeta_gmu_window_bytes[ZetaGmuWindows];
typedef enum {
    ZetaGmuSuccess, ZetaGmuArgument, ZetaGmuFirmware, ZetaGmuBusy, ZetaGmuIoError, ZetaGmuStateMismatch,
    ZetaGmuTimeout, ZetaGmuClockError, ZetaGmuPoisoned, ZetaGmuFault, ZetaGmuProtocolError
} ZetaGmuStatus;
typedef struct {
    void *cookie;
    size_t bytes[ZetaGmuWindows];
    int (*read32)(void *, unsigned window, size_t byte_offset, uint32_t *);
    int (*write32)(void *, unsigned window, size_t byte_offset, uint32_t);
    int (*barrier)(void *);
} ZetaGmuIo;
typedef struct {
    void *cookie;
    int (*sha256)(void *, const void *, size_t, uint8_t digest[32]);
    int (*now_us)(void *, uint64_t *);
    int (*wait_us)(void *, unsigned);
} ZetaGmuServices;
/* CPU view and GMU address of one payload of the GMU's SMMU context (NativeAdrenoGmuContextPayloads order). */
typedef struct {volatile uint32_t *cpu; size_t bytes; uint64_t iova;} ZetaGmuMemory;
typedef struct {
    const uint8_t *firmware; size_t firmware_bytes;   /* a660_gmu.bin of the stock vendor image, hash-pinned */
    ZetaGmuMemory icache, dummy, debug, log, hfi;
    unsigned poll_budget;                             /* per poll; each poll also stops at 100 ms, GMU_START_TIMEOUT */
} ZetaGmuConfig;
typedef struct {
    ZetaGmuIo io; ZetaGmuServices services; AdrenoHfi hfi;
    uint32_t poisoned, boot_attempted;
    AdrenoHfiStartup startup;
} ZetaGmuDevice;
typedef struct {
    uint32_t phase, write_attempts, read_attempts, poll_reads;
    uint32_t hash_verified, blocks, reset_verified;
    uint32_t sysreset_before, hfi_status_before, rsc_busy_before, general7_before;
    uint32_t core_version, hfi_version, firmware_init_result, hfi_status, firmware_ready, hfi_ready;
    uint32_t ao_fault_status, cm3_fault_status;
    uint8_t sha256[32];
} ZetaGmuResult;
typedef struct {unsigned polls_per_command, wait_interval_us; uint64_t command_timeout_us, total_timeout_us;} ZetaGmuLimits;
typedef struct {
    ZetaGmuResult load;
    AdrenoHfiStartupResult protocol;
    AdrenoHfiStartupStatus protocol_status;
    ZetaGmuStatus health_status;
} ZetaGmuStartupResult;
/* a6xx_gmu_first_boot from the firmware load on: the caller has CX on, the GMU clocks at the stock rates (gmu 200 MHz,
 * hub 150 MHz), the GMU SMMU context live with the payloads mapped, and the GMU in reset. Refuses before any write unless
 * the GMU reads in reset with HFI not ready and the RSC idle, and the firmware matches its pinned hash. Then: load the
 * blocks (ITCM/DTCM through the GMU window, the cache region into its payload), a6xx_gmu_register_config, the version
 * words, the interrupt clear/mask, a6xx_gmu_device_start, the PDC (in AOP: start address and enable only) and RSC
 * sequences, a6xx_gmu_hfi_start, then the HFI startup messages. One attempt per device; a failure after the first write
 * puts the CM3 back in reset and poisons the device. */
ZetaGmuStatus ZetaGmuColdStart(ZetaGmuDevice *, const ZetaGmuConfig *, const AdrenoHfiStartupConfig *, const ZetaGmuLimits *,
                               ZetaGmuStartupResult *);
typedef struct {volatile unsigned char *cpu; uint64_t physical; size_t bytes;} ZetaGmuMmioWindow;
typedef struct {ZetaGmuMmioWindow windows[ZetaGmuWindows];} ZetaGmuMmio;
/* Direct volatile 32-bit access plus dsb sy over owned Device mappings of exactly the windows above. */
ZetaGmuStatus ZetaGmuBindMmio(ZetaGmuMmio *, ZetaGmuIo *);

/* Votes. The AOP command DB (stock reserved-memory@80860000, 0x20000 bytes): the ARC level tables of gfx.lvl, cx.lvl,
 * mx.lvl and the BCM SH0, MC0, ACV, CN0 records. */
typedef struct {const uint8_t *data; size_t bytes; uint32_t address;} ZetaGmuDbEntry;
typedef struct {ZetaGmuDbEntry gfx, cx, mx, sh0, mc0, acv, cn0;} ZetaGmuDbInputs;
typedef enum {ZetaGmuDbSuccess, ZetaGmuDbArgument, ZetaGmuDbMagic, ZetaGmuDbCorrupt, ZetaGmuDbDuplicate, ZetaGmuDbMissing}
    ZetaGmuDbStatus;
ZetaGmuDbStatus ZetaGmuCommandDbInputs(const uint8_t *db, size_t bytes, ZetaGmuDbInputs *out);
/* The stock DT power-level bin for the qfprom speed-bin fuse (0x784000 + 0x17b, bits 5..7): bins 0/5/7 top at 840 MHz,
 * 1/3 at 900 MHz. Returns 0 for a fuse value the stock DT has no table for. */
unsigned ZetaGmuGpuLevels(unsigned speed_bin);
/* build_dcvs_table + build_bw_table of adreno_a6xx_rpmh.c for that bin and the LPDDR5 (ddr8) bus table; ACD and IFPC off.
 * The command DB values are the board's, never defaults. */
AdrenoHfiStartupStatus ZetaGmuBuildStartup(const ZetaGmuDbInputs *, unsigned speed_bin, AdrenoHfiStartupConfig *);
/* kgsl_pwrctrl_set_default_gpu_pwrlevel's first GX_BW_PERF_VOTE through a6xx_gmu_dcvs_set: the HFI perf index of the
 * bin's qcom,initial-pwrlevel and that level's qcom,bus-freq-ddr8. `level` overrides the stock index (DT order, 0 =
 * fastest) when below the bin's level count. */
void ZetaGmuDefaultVote(unsigned speed_bin, unsigned level, uint32_t *perf, uint32_t *bandwidth);
#ifdef __cplusplus
}
#endif
#endif
