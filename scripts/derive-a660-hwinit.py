#!/usr/bin/env python3
"""Generate package/ZetaA660HwInit.h from the stock Surface Duo 2 KGSL source.

usage: derive-a660-hwinit.py <kernel/msm-5.4/drivers/gpu/msm> package/ZetaA660HwInit.h

The tables are the stock driver's for adreno_gpu_core_a660v2, with every register resolved to its a6xx_reg.h dword offset."""
import re, sys
from pathlib import Path
M = Path(sys.argv[1])
regs = {}
for line in (M / 'a6xx_reg.h').read_text().splitlines():
    m = re.match(r'#define\s+(A6XX_\w+)\s+\(?(0[xX][0-9a-fA-F]+|\d+)\)?\s*(?:/\*.*)?$', line)
    if m: regs[m.group(1)] = int(m.group(2), 0)
def val(expr):
    expr = expr.strip()
    m = re.match(r'(A6XX_\w+)\s*(?:\+\s*(\d+))?$', expr)
    if m: return regs[m.group(1)] + int(m.group(2) or 0)
    return int(expr, 0)
gl = (M / 'adreno-gpulist.h').read_text()
a6 = (M / 'adreno_a6xx.c').read_text()
def block(text, name):
    m = re.search(re.escape(name) + r'\[\] = \{(.*?)\n\};', text, re.S)
    return m.group(1)
hwcg = [(val(a), int(b, 16)) for a, b in re.findall(r'\{(A6XX_\w+),\s*(0x[0-9a-fA-F]+)\}', block(gl, 'a660_hwcg_regs'))]
prot = [(val(a), int(s, 16), int(e, 16), int(n)) for a, s, e, n in
        re.findall(r'\{\s*(A6XX_CP_PROTECT_REG\s*\+\s*\d+),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*(\d)\s*\}', block(gl, 'a660_protected_regs'))]
gbif = [(val(a), int(b, 16)) for a, b in re.findall(r'\{(A6XX_\w+),\s*(0x[0-9a-fA-F]+)\}', block(gl, 'a650_gbif_regs'))]
def lst(name): return [val(x) for x in re.findall(r'(A6XX_\w+\s*(?:\+\s*\d+)?)', block(a6, name))]
out = ['/* SPDX-License-Identifier: BSD-2-Clause-Patent */',
       '/* Generated from the stock Surface Duo 2 KGSL source (msm-5.4 drivers/gpu/msm, matching msm_kgsl.ko 5.4.233):',
       ' * adreno-gpulist.h a660_hwcg_regs, a660_protected_regs (encoded as a6xx_protect_init writes them), a650_gbif_regs, and',
       ' * adreno_a6xx.c\'s power-up lists for the a650 family, with every register as its a6xx_reg.h dword offset.',
       ' * scripts/derive-a660-hwinit.py writes this file; do not edit it by hand. */',
       '#ifndef ZETA_A660_HW_INIT_H', '#define ZETA_A660_HW_INIT_H', '#include <stdint.h>']
def table(name, rows, width):
    out.append(f'static const uint32_t {name}[][{width}] = {{')
    for r in rows: out.append('    {' + ', '.join(f'0x{x:05x}' if i == 0 else f'0x{x:08x}' for i, x in enumerate(r)) + '},')
    out.append('};')
table('ZetaA660Hwcg', hwcg, 2)
table('ZetaA660Protect', [(r, (s & 0x3ffff) | (((e - s) & 0x1fff) << 18) | (n << 31)) for r, s, e, n in prot], 2)
table('ZetaA650Gbif', gbif, 2)
for name, cname in (('a6xx_ifpc_pwrup_reglist', 'ZetaA6xxIfpcPwrup'), ('a650_ifpc_pwrup_reglist', 'ZetaA650IfpcPwrup'),
                    ('a6xx_pwrup_reglist', 'ZetaA6xxPwrup'), ('a650_pwrup_reglist', 'ZetaA650Pwrup')):
    v = lst(name)
    out.append(f'static const uint32_t {cname}[] = {{')
    for i in range(0, len(v), 8): out.append('    ' + ', '.join(f'0x{x:05x}' for x in v[i:i + 8]) + ',')
    out.append('};')
names = ['CP_ADDR_MODE_CNTL', 'VSC_ADDR_MODE_CNTL', 'GRAS_ADDR_MODE_CNTL', 'RB_ADDR_MODE_CNTL', 'PC_ADDR_MODE_CNTL',
         'HLSQ_ADDR_MODE_CNTL', 'VFD_ADDR_MODE_CNTL', 'VPC_ADDR_MODE_CNTL', 'UCHE_ADDR_MODE_CNTL', 'SP_ADDR_MODE_CNTL',
         'TPL1_ADDR_MODE_CNTL', 'RBBM_SECVID_TSB_ADDR_MODE_CNTL', 'RBBM_PERFCTR_GPU_BUSY_MASKED', 'UCHE_WRITE_RANGE_MAX_LO',
         'UCHE_TRAP_BASE_LO', 'UCHE_WRITE_THRU_BASE_LO', 'UCHE_FILTER_CNTL', 'UCHE_CACHE_WAYS', 'CP_ROQ_THRESHOLDS_2',
         'CP_ROQ_THRESHOLDS_1', 'CP_LPAC_PROG_FIFO_SIZE', 'CP_MEM_POOL_SIZE', 'PC_DBG_ECO_CNTL', 'CP_AHB_CNTL',
         'RBBM_PERFCTR_CNTL', 'RB_NC_MODE_CNTL', 'TPL1_NC_MODE_CNTL', 'SP_NC_MODE_CNTL', 'UCHE_MODE_CNTL',
         'RBBM_INTERFACE_HANG_INT_CNTL', 'UCHE_CLIENT_PF', 'TPL1_BICUBIC_WEIGHTS_TABLE_0', 'RBBM_CLOCK_CNTL',
         'GPU_GMU_AO_GPU_CX_BUSY_MASK', 'GMU_CX_GMU_POWER_COUNTER_SELECT_0', 'GMU_CX_GMU_POWER_COUNTER_SELECT_1',
         'GMU_CX_GMU_POWER_COUNTER_ENABLE', 'CP_PROTECT_CNTL', 'CP_CHICKEN_DBG', 'RBBM_GBIF_CLIENT_QOS_CNTL',
         'UCHE_CMDQ_CONFIG', 'CP_APRIV_CNTL', 'RBBM_SECVID_TSB_CNTL', 'RBBM_SECVID_TRUST_CNTL',
         'GPU_GMU_AO_GMU_CGC_MODE_CNTL', 'GPU_GMU_AO_GMU_CGC_DELAY_CNTL', 'GPU_GMU_AO_GMU_CGC_HYST_CNTL',
         'GMU_CX_GMU_WFI_CONFIG', 'GPU_GMU_GX_SPTPRAC_CLOCK_CONTROL', 'UCHE_GBIF_GX_CONFIG', 'GBIF_HALT', 'RBBM_GBIF_HALT',
         'CP_SQE_INSTR_BASE_LO', 'CP_SQE_CNTL', 'RBBM_INT_0_MASK', 'RBBM_INT_0_STATUS', 'RBBM_INT_CLEAR_CMD', 'RBBM_STATUS',
         'RBBM_STATUS3', 'CP_HW_FAULT', 'CP_RB_RPTR', 'CP_RB_WPTR', 'CP_SQE_STAT_ADDR', 'CP_SQE_STAT_DATA', 'RBBM_SW_RESET_CMD',
         'CP_PROTECT_STATUS', 'CP_INTERRUPT_STATUS']
out.append('enum {')
for n in names:
    if 'A6XX_' + n not in regs: raise SystemExit('missing ' + n)
    out.append(f'    ZETA_{n} = 0x{regs["A6XX_" + n]:05x},')
out += ['};', '#endif', '']
Path(sys.argv[2]).write_text('\n'.join(out))
print(len(hwcg), len(prot), len(gbif))
