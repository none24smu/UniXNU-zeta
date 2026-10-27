source_filename = "duo_solid_fragment"
target datalayout = "e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v16:16:16-v24:32:32-v32:32:32-v48:64:64-v64:64:64-v96:128:128-v128:128:128-v192:256:256-v256:256:256-v512:512:512-v1024:1024:1024-n8:16:32"
target triple = "air64-apple-ios27.1.0"

define <{ <4 x float> }> @duo_solid_fragment() {
  %out = insertvalue <{ <4 x float> }> undef, <4 x float> <float 2.500000e-01, float 5.000000e-01, float 1.250000e-01, float 2.500000e-01>, 0
  ret <{ <4 x float> }> %out
}
!air.version = !{!0}
!air.language_version = !{!1}
!air.fragment = !{!2}
!0 = !{i32 2, i32 9, i32 0}
!1 = !{!"Metal", i32 4, i32 1, i32 0}
!2 = !{ptr @duo_solid_fragment, !3, !5}
!3 = !{!4}
!4 = !{!"air.render_target", i32 0, i32 0, !"air.arg_type_name", !"float4", !"air.arg_name", !"out"}
!5 = !{}

