/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* The HFI vote tables of the stock A660 driver: adreno_a6xx_rpmh.c build_dcvs_table / build_bw_table (msm_kgsl.ko 5.4.233)
 * over the AOP command DB, which is parsed as cmd-db.c reads it (sheng package/ShengGmuCommandDb.c's checks). The power
 * levels are the stock DT's qcom,gpu-pwrlevel-bins (vendor_boot Lahaina V2.1) with the LPDDR5 qcom,bus-table-ddr8. */
#include "ZetaGmu.h"

static uint16_t u16(const uint8_t *p) {return (uint16_t)(p[0] | (uint16_t)p[1] << 8);}
static uint32_t u32(const uint8_t *p) {return u16(p) | (uint32_t)u16(p + 2) << 16;}
static int range(size_t at, size_t len, size_t size) {return at <= size && len <= size - at;}

ZetaGmuDbStatus ZetaGmuCommandDbInputs(const uint8_t *data, size_t bytes, ZetaGmuDbInputs *out)
{
    if (!data || !out || bytes < 144) return ZetaGmuDbArgument;
    if (u32(data + 4) != 0x0c0330db) return ZetaGmuDbMagic;   /* CMD_DB_MAGIC */
    /* struct cmd_db_header: version, magic, rsc_hdr[8] (16 bytes each), checksum, reserved, then data at 144. The slave
     * table ends at the first zero slv_id; each entry_header is 24 bytes (id[8], priority[2], addr, len, offset). */
    static const char names[7][8] = {"gfx.lvl", "cx.lvl", "mx.lvl", "SH0", "MC0", "ACV", "CN0"};
    static const unsigned slaves[7] = {3, 3, 3, 5, 5, 5, 5};   /* CMD_DB_HW_ARC, CMD_DB_HW_BCM */
    ZetaGmuDbEntry found[7] = {{0}};
    unsigned seen = 0;
    for (unsigned i = 0; i < 8; ++i) {
        const uint8_t *h = data + 8 + 16 * i;
        const unsigned slave = u16(h);
        if (!slave) break;
        const size_t head = 144u + u16(h + 2), aux = 144u + u16(h + 4), count = u16(h + 6);
        if (!range(head, count * 24, bytes) || !range(aux, 0, bytes)) return ZetaGmuDbCorrupt;
        for (size_t at = head; at < head + count * 24; at += 24) {
            const uint8_t *e = data + at;
            for (unsigned n = 0; n < 7; ++n) {
                unsigned same = 1;
                for (unsigned k = 0; k < 8 && same; ++k) same = e[k] == (uint8_t)names[n][k];
                if (!same) continue;
                const uint32_t address = u32(e + 16);
                const size_t len = u16(e + 20), offset = aux + u16(e + 22);
                if (seen & (1u << n)) return ZetaGmuDbDuplicate;
                if (slave != slaves[n] || !address || (address & 3) || ((address >> 16) & 7) != slave ||
                    !range(offset, len, bytes)) return ZetaGmuDbCorrupt;
                seen |= 1u << n;
                found[n] = (ZetaGmuDbEntry){data + offset, len, address};
            }
        }
    }
    if (seen != 0x7f) return ZetaGmuDbMissing;
    *out = (ZetaGmuDbInputs){found[0], found[1], found[2], found[3], found[4], found[5], found[6]};
    return ZetaGmuDbSuccess;
}

/* Stock power levels, fastest first as in the DT: gpu-freq, qcom,level (RPMh VLVL), qcom,bus-freq-ddr8. Bins 1 and 3 add
 * 900 MHz at the top; all bins share the rest. */
typedef struct {uint32_t hz, vlvl, bus;} Level;
static const Level levels[] = {
    {900000000, 0x1b0, 11}, {840000000, 0x1a0, 11}, {778000000, 0x180, 11}, {738000000, 0x140, 11}, {676000000, 0x100, 10},
    {608000000, 0x0e0, 7}, {540000000, 0x0c0, 7}, {491000000, 0x090, 7}, {443000000, 0x080, 7}, {379000000, 0x050, 6},
    {315000000, 0x040, 2}};
static const uint32_t ddr8_kbps[] = {0, 781250, 1761718, 2136718, 2660156, 3000000, 3972656, 6074218, 6671875, 8171875,
                                     10687500, 12484375};
static const uint32_t cnoc_kbps[] = {0, 100};
#define LEVELS (sizeof levels / sizeof levels[0])
#define RPMH_REGULATOR_LEVEL_MIN_SVS 48
#define GMU_FREQUENCY 200000000

unsigned ZetaGmuGpuLevels(unsigned bin)
{
    switch (bin) {
    case 0: case 5: case 7: return LEVELS - 1;
    case 1: case 3: return LEVELS;
    default: return 0;
    }
}
static const Level *bin_levels(unsigned bin) {return levels + (LEVELS - ZetaGmuGpuLevels(bin));}

/* rpmh_arc_cmds: the level count ends at the first zero after a non-zero entry. */
static unsigned arc_count(const ZetaGmuDbEntry *e)
{
    const unsigned n = (unsigned)(e->bytes / 2);
    unsigned num = 1;
    for (; num < n; ++num) if (u16(e->data + 2 * (num - 1)) && !u16(e->data + 2 * num)) break;
    return n ? num : 0;
}
/* setup_volt_dependency_tbl. */
static int arc_votes(uint32_t *votes, const ZetaGmuDbEntry *pri, const ZetaGmuDbEntry *sec, const uint16_t *vlvl, unsigned n)
{
    const unsigned pn = arc_count(pri), sn = arc_count(sec);
    if (!pn || !sn) return -1;
    for (unsigned i = 0; i < n; ++i) {
        unsigned k = 0, j = 0;
        while (k < pn && u16(pri->data + 2 * k) < vlvl[i]) ++k;
        if (k == pn) return -1;
        const uint16_t cur = u16(pri->data + 2 * k);
        for (j = 0; j < sn; ++j) if (u16(sec->data + 2 * j) >= cur || j + 1 == sn) break;
        if (j == sn) j = 0;
        votes[i] = (uint32_t)cur << 16 | (j & 0xff) << 8 | (k & 0xff);
    }
    return 0;
}
/* struct bcm and the cmd-db bcm_data aux record (unit le32, width le16, vcd u8). */
typedef struct {uint32_t address, unit, buswidth; uint16_t width; uint8_t vcd, fixed;} Bcm;
static int bcm(Bcm *b, const ZetaGmuDbEntry *e, uint32_t buswidth, uint8_t fixed)
{
    if (e->bytes < 8) return -1;
    *b = (Bcm){e->address, u32(e->data), buswidth, u16(e->data + 4), e->data[6], fixed};
    return !fixed && (!b->unit || !b->width || !buswidth) ? -1 : 0;
}
/* tcs_cmd_data with ab 0 and ib the level's KB/s; BCM_TCS_CMD(commit, valid, x, y). */
static void tcs_data(const Bcm *bcms, unsigned count, uint32_t ib, uint32_t *data)
{
    for (unsigned i = 0; i < count; ++i) {
        const uint32_t commit = i == count - 1 || bcms[i].vcd != bcms[i + 1].vcd;
        if (bcms[i].fixed) {data[i] = commit << 30 | (ib ? (1u << 29 | 0x8u) : 0); continue;}
        uint64_t y = (uint64_t)ib * bcms[i].width / bcms[i].buswidth * 1000 / bcms[i].unit;
        if (ib && !y) y = 1;
        if (y > 0x3fff) y = 0x3fff;
        data[i] = commit << 30 | (y ? 1u << 29 : 0) | (uint32_t)y;
    }
}
static uint32_t wait_mask(const Bcm *bcms, unsigned count)
{
    uint32_t mask = 0;
    for (unsigned i = 0; i < count; ++i) if (i == count - 1 || bcms[i].vcd != bcms[i + 1].vcd) mask |= 1u << i;
    return mask;
}

AdrenoHfiStartupStatus ZetaGmuBuildStartup(const ZetaGmuDbInputs *in, unsigned bin, AdrenoHfiStartupConfig *out)
{
    const unsigned n = ZetaGmuGpuLevels(bin);
    if (!in || !out || !n) return AdrenoHfiStartupInvalid;
    const Level *l = bin_levels(bin);
    AdrenoHfiStartupConfig c = {0};
    uint32_t votes[16];
    uint16_t vlvl[16] = {0};
    /* setup_cx_arc_votes: GMU levels 0 and GMU_FREQUENCY at MIN_SVS, cx over mx. */
    const uint16_t cx_vlvl[2] = {0, RPMH_REGULATOR_LEVEL_MIN_SVS};
    if (arc_votes(votes, &in->cx, &in->mx, cx_vlvl, 2)) return AdrenoHfiStartupInvalid;
    c.gmu_count = 2;
    c.gmu[0] = (AdrenoHfiPerformanceLevel){0, votes[0]};
    c.gmu[1] = (AdrenoHfiPerformanceLevel){GMU_FREQUENCY, votes[1]};
    /* setup_gx_arc_votes: a zero level, then the DT levels slowest first, gfx over mx. */
    c.gpu_count = n + 1;
    if (c.gpu_count > arc_count(&in->gfx)) return AdrenoHfiStartupInvalid;
    for (unsigned i = 0; i < n; ++i) vlvl[1 + i] = (uint16_t)l[n - 1 - i].vlvl;
    if (arc_votes(votes, &in->gfx, &in->mx, vlvl, c.gpu_count)) return AdrenoHfiStartupInvalid;
    c.gpu[0] = (AdrenoHfiPerformanceLevel){0, votes[0]};
    for (unsigned i = 0; i < n; ++i) c.gpu[1 + i] = (AdrenoHfiPerformanceLevel){l[n - 1 - i].hz, votes[1 + i]};
    /* build_bw_table: a660_ddr_bcms SH0 (buswidth 16), MC0 (4), ACV (fixed); a660_cnoc_bcms CN0 (4). */
    Bcm ddr[3], cnoc[1];
    if (bcm(ddr + 0, &in->sh0, 16, 0) || bcm(ddr + 1, &in->mc0, 4, 0) || bcm(ddr + 2, &in->acv, 0, 1) ||
        bcm(cnoc, &in->cn0, 4, 0)) return AdrenoHfiStartupInvalid;
    c.bandwidth_count = sizeof ddr8_kbps / sizeof ddr8_kbps[0];
    c.ddr_count = 3; c.ddr_wait_mask = wait_mask(ddr, 3);
    for (unsigned j = 0; j < 3; ++j) c.ddr_addresses[j] = ddr[j].address;
    for (unsigned i = 0; i < c.bandwidth_count; ++i) tcs_data(ddr, 3, ddr8_kbps[i], c.ddr_data[i]);
    c.cnoc_count = 1; c.cnoc_wait_mask = wait_mask(cnoc, 1);
    c.cnoc_addresses[0] = cnoc[0].address;
    for (unsigned i = 0; i < 2; ++i) tcs_data(cnoc, 1, cnoc_kbps[i], c.cnoc_data[i]);
    if (AdrenoHfiStartupValidate(&c) != AdrenoHfiStartupSuccess) return AdrenoHfiStartupInvalid;
    *out = c;
    return AdrenoHfiStartupSuccess;
}

void ZetaGmuDefaultVote(unsigned bin, unsigned level, uint32_t *perf, uint32_t *bandwidth)
{
    const unsigned n = ZetaGmuGpuLevels(bin);
    if (!n) {if (perf) *perf = 1; if (bandwidth) *bandwidth = 1; return;}
    /* qcom,initial-pwrlevel: the slowest level in every stock bin. */
    if (level >= n) level = n - 1;
    /* a6xx_gmu_dcvs_set: freq = gpu_level_num - pwrlevel - 1, bw = that level's bus index. */
    if (perf) *perf = (n + 1) - level - 1;
    if (bandwidth) *bandwidth = bin_levels(bin)[level].bus;
}
