; SPDX-License-Identifier: MIT
; The default branch needs an absent symbol. Successful creation therefore also
; proves that specialization of a linked function survives the frontend/C ABI.
target triple = "air64_v28-apple-macosx26.0.0"
target datalayout = "e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v16:16:16-v32:32:32-v64:64:64-v128:128:128-n8:16:32"
@enabled.MTL_FC_INIT_0_b = internal addrspace(2) constant i8 0, align 1

define float @vertex_gain() {
  %value = load i8, ptr addrspace(2) @enabled.MTL_FC_INIT_0_b
  %enabled = icmp ne i8 %value, 0
  br i1 %enabled, label %good, label %bad
good:
  ret float 1.0
bad:
  %missing = call float @absent.MTL_VISIBLE_FN_REF()
  ret float %missing
}
define float @fragment_gain() {
  %value = load i8, ptr addrspace(2) @enabled.MTL_FC_INIT_0_b
  %enabled = icmp ne i8 %value, 0
  br i1 %enabled, label %good, label %bad
good:
  ret float 0.5
bad:
  %missing = call float @absent.MTL_VISIBLE_FN_REF()
  ret float %missing
}
define float @unused_gain() { ret float 0.25 }
declare float @absent.MTL_VISIBLE_FN_REF() section "air.externally_defined"
!air.visible = !{!0, !4, !5}
!air.visible_function_references = !{!6}
!air.function_constants = !{!7}
!air.version = !{!8}
!air.language_version = !{!9}
!0 = !{ptr @vertex_gain, !1, !3}
!1 = !{!2}
!2 = !{!"air.visible_output", !"air.arg_type_name", !"float"}
!3 = !{}
!4 = !{ptr @fragment_gain, !1, !3}
!5 = !{ptr @unused_gain, !1, !3}
!6 = !{!"air.visible_function_reference", ptr @absent.MTL_VISIBLE_FN_REF, !"absent"}
!7 = !{ptr addrspace(2) @enabled.MTL_FC_INIT_0_b, !"bool", !"enabled", i32 0}
!8 = !{i32 2, i32 8, i32 0}
!9 = !{!"Metal", i32 4, i32 0, i32 0}
