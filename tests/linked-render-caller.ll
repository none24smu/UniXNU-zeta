; SPDX-License-Identifier: MIT
; Owned AIR fixture: both render stages require a different visible function.
target triple = "air64_v28-apple-macosx26.0.0"

define <4 x float> @linked_vertex(ptr addrspace(1) %positions, i32 %id) {
  %gain = call float @vertex_gain.MTL_VISIBLE_FN_REF()
  %i = zext i32 %id to i64
  %p = getelementptr <2 x float>, ptr addrspace(1) %positions, i64 %i
  %xy = load <2 x float>, ptr addrspace(1) %p, align 8
  %x = extractelement <2 x float> %xy, i32 0
  %y = extractelement <2 x float> %xy, i32 1
  %scaled = fmul float %x, %gain
  %a = insertelement <4 x float> <float 0.0, float 0.0, float 0.0, float 1.0>, float %scaled, i32 0
  %b = insertelement <4 x float> %a, float %y, i32 1
  ret <4 x float> %b
}

define <4 x float> @linked_fragment() {
  %gain = call float @fragment_gain.MTL_VISIBLE_FN_REF()
  %color = insertelement <4 x float> <float 0.0, float 0.0, float 0.0, float 1.0>, float %gain, i32 1
  ret <4 x float> %color
}

declare float @vertex_gain.MTL_VISIBLE_FN_REF() section "air.externally_defined"
declare float @fragment_gain.MTL_VISIBLE_FN_REF() section "air.externally_defined"
!air.vertex = !{!0}
!air.fragment = !{!5}
!air.visible_function_references = !{!8, !9}
!air.version = !{!10}
!air.language_version = !{!11}
!0 = !{ptr @linked_vertex, !1, !3}
!1 = !{!2}
!2 = !{!"air.position", !"air.arg_type_name", !"float4", !"air.arg_name", !"position"}
!3 = !{!4, !12}
!4 = !{i32 0, !"air.buffer", !"air.location_index", i32 0, i32 1, !"air.read", !"air.address_space", i32 1, !"air.arg_type_size", i32 8, !"air.arg_type_align_size", i32 8, !"air.arg_type_name", !"float2", !"air.arg_name", !"positions"}
!5 = !{ptr @linked_fragment, !6, !7}
!6 = !{!13}
!7 = !{}
!8 = !{!"air.visible_function_reference", ptr @vertex_gain.MTL_VISIBLE_FN_REF, !"vertex_gain"}
!9 = !{!"air.visible_function_reference", ptr @fragment_gain.MTL_VISIBLE_FN_REF, !"fragment_gain"}
!10 = !{i32 2, i32 8, i32 0}
!11 = !{!"Metal", i32 4, i32 0, i32 0}
!12 = !{i32 1, !"air.vertex_id", !"air.arg_type_name", !"uint", !"air.arg_name", !"id"}
!13 = !{!"air.render_target", i32 0, i32 0, !"air.arg_type_name", !"float4"}
