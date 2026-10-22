// SPDX-License-Identifier: BSD-2-Clause-Patent
// Linked-driver counters only; no MMIO and no device command.
.text
.global _start
_start:
  sub sp, sp, #112
  stp x19, x20, [sp, #80]
  str x30, [sp, #104]
  mov w19, #:abs_g0:ufs_settle_ms
inspect_state:
  adrp x8, ufs_probe_calls
  ldr w9, [x8, :lo12:ufs_probe_calls]
  str x9, [sp]
  adrp x8, ufs_matched
  ldr w9, [x8, :lo12:ufs_matched]
  str x9, [sp, #8]
  adrp x8, ufs_probe_requested
  ldr w9, [x8, :lo12:ufs_probe_requested]
  str x9, [sp, #16]
  adrp x8, ufs_mapped
  ldr w9, [x8, :lo12:ufs_mapped]
  str x9, [sp, #24]
  adrp x8, ufs_status
  ldr w9, [x8, :lo12:ufs_status]
  str x9, [sp, #32]
  adrp x8, ufs_root_step
  ldr w9, [x8, :lo12:ufs_root_step]
  str x9, [sp, #40]
  adrp x8, ufs_root_diagnostic
  ldr x9, [x8, :lo12:ufs_root_diagnostic]
  str x9, [sp, #48]
  str wzr, [sp, #64]
  adr x0, probe_arg
  add x1, sp, #64
  mov w2, #4
  bl ufs_parse_arg
  ldr w9, [sp, #64]
  str x9, [sp, #56]
  adr x0, message
  bl ufs_printf
  cbz w19, finished
  mov w20, #1000
  cmp w19, w20
  csel w20, w19, w20, lo
  mov w0, w20
  bl ufs_sleep
  sub w19, w19, w20
  b inspect_state
finished:
  ldp x19, x20, [sp, #80]
  ldr x30, [sp, #104]
  add sp, sp, #112
  ret
message:
  .asciz "ZETA UFS STATE: probe_calls=%llx matched=%llx requested=%llx mapped=%llx status=%llx root_step=%llx stage=%s probe=%llx\n"
probe_arg:
  .asciz "native-ufs-probe"
