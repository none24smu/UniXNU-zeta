// SPDX-License-Identifier: BSD-2-Clause-Patent
// Stock zeta apps-smmu@15000000, UFS SID 0xe0. SMMUv2 GR0/GR1 only.
// Does not modify SMMU state or dereference firmware DMA addresses.
.text
.global _start
_start:
  sub sp, sp, #128
  str x30, [sp, #120]
  stp xzr, xzr, [sp]
  stp xzr, xzr, [sp, #16]
  stp xzr, xzr, [sp, #32]
  stp xzr, xzr, [sp, #48]
  stp xzr, xzr, [sp, #64]
  stp xzr, xzr, [sp, #80]
  stp xzr, xzr, [sp, #96]
  mov x0, #0x15000000
  mov x1, #0x2000
  bl ufs_mapper
  cbz x0, report_smmu
  mov x13, x0
  mov x8, #1
  str x8, [sp, #104]
  ldr w8, [x13]
  ldr w9, [x13, #0x20]
  ldr w10, [x13, #0x24]
  ldr w11, [x13, #0x28]
  stp x8, x9, [sp]
  stp x10, x11, [sp, #16]
  ldr w8, [x13, #0x48]
  str x8, [sp, #32]
  and w8, w9, #255
  mov w9, #128
  cmp w8, w9
  csel w8, w8, w9, ls
  str x8, [sp, #40]
  mov x9, #0
  mov x14, #0
  mov x15, #0
  mov x16, #0xffff
  add x2, x13, #0x800
  add x3, x13, #0xc00
scan_smmu:
  cmp w9, w8
  b.hs scan_complete
  ldr w10, [x2, x9, lsl #2]
  tbz w10, #31, next_smr
  add x14, x14, #1
  lsr w12, w10, #16
  and w12, w12, #0x7fff
  eor w11, w10, #0xe0
  and w11, w11, #0x7fff
  bic w11, w11, w12
  cbnz w11, next_smr
  add x15, x15, #1
  cmp x15, #1
  b.ne next_smr
  mov x16, x9
  str x10, [sp, #72]
  ldr w11, [x3, x9, lsl #2]
  str x11, [sp, #80]
next_smr:
  add x9, x9, #1
  b scan_smmu
scan_complete:
  stp x14, x15, [sp, #48]
  str x16, [sp, #64]
  cbz x15, report_smmu
  ldr w11, [sp, #80]
  ubfx w9, w11, #16, #2
  cbnz w9, report_smmu
  and w9, w11, #255
  ldr w10, [sp, #16]
  and w10, w10, #255
  cmp w9, w10
  b.hs report_smmu
  add x2, x13, #0x1000
  add x3, x2, #0x800
  ldr w10, [x2, x9, lsl #2]
  ldr w11, [x3, x9, lsl #2]
  stp x10, x11, [sp, #88]
report_smmu:
  adr x0, smmu_format
  bl ufs_printf
  ldr x30, [sp, #120]
  add sp, sp, #128
  ret
smmu_format:
  .asciz "ZETA SMMU RO: CR0=%llx IDR0=%llx IDR1=%llx IDR2=%llx GFSR=%llx groups=%llx valid=%llx matches=%llx index=%llx SMR=%llx S2CR=%llx CBAR=%llx CBA2R=%llx read=%llx\n"
