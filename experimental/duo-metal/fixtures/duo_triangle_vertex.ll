source_filename = "duo_triangle_vertex"
target datalayout = "e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v16:16:16-v24:32:32-v32:32:32-v48:64:64-v64:64:64-v96:128:128-v128:128:128-v192:256:256-v256:256:256-v512:512:512-v1024:1024:1024-n8:16:32"
target triple = "air64-apple-ios27.1.0"

define <{ <4 x float> }> @duo_triangle_vertex(i32 %id) {
  %one = icmp eq i32 %id, 1
  %two = icmp eq i32 %id, 2
  %x = select i1 %one, float 3.000000e+00, float -1.000000e+00
  %y = select i1 %two, float 3.000000e+00, float -1.000000e+00
  %v0 = insertelement <4 x float> undef, float %x, i32 0
  %v1 = insertelement <4 x float> %v0, float %y, i32 1
  %v2 = insertelement <4 x float> %v1, float 0.000000e+00, i32 2
  %v3 = insertelement <4 x float> %v2, float 1.000000e+00, i32 3
  %out = insertvalue <{ <4 x float> }> undef, <4 x float> %v3, 0
  ret <{ <4 x float> }> %out
}
!air.version = !{!0}
!air.language_version = !{!1}
!air.vertex = !{!2}
!0 = !{i32 2, i32 9, i32 0}
!1 = !{!"Metal", i32 4, i32 1, i32 0}
!2 = !{ptr @duo_triangle_vertex, !3, !5}
!3 = !{!4}
!4 = !{!"air.position", !"air.arg_type_name", !"float4", !"air.arg_name", !"out"}
!5 = !{!6}
!6 = !{i32 0, !"air.vertex_id", !"air.arg_type_name", !"uint", !"air.arg_name", !"id"}
