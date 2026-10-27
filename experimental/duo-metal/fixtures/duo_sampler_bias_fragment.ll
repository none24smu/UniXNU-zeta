source_filename = "duo_sampler_bias_fragment"
target datalayout = "e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v16:16:16-v24:32:32-v32:32:32-v48:64:64-v64:64:64-v96:128:128-v128:128:128-v192:256:256-v256:256:256-v512:512:512-v1024:1024:1024-n8:16:32"
target triple = "air64-apple-ios27.1.0"
@__air_sampler_state = internal addrspace(2) constant [2 x i64] [i64 34901797601050697, i64 1], align 8
declare { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1), ptr addrspace(2), <2 x float>, i1, <2 x i32>, i1, float, float, i32)
define <{ <4 x float> }> @duo_sampler_bias_fragment(ptr addrspace(1) %texture) {
  %sample = call { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr addrspace(1) %texture, ptr addrspace(2) @__air_sampler_state, <2 x float> <float 1.500000e+00, float 5.000000e-01>, i1 true, <2 x i32> zeroinitializer, i1 false, float 0.000000e+00, float 0.000000e+00, i32 0)
  %value = extractvalue { <4 x float>, i8 } %sample, 0
  %out = insertvalue <{ <4 x float> }> undef, <4 x float> %value, 0
  ret <{ <4 x float> }> %out
}
!air.version = !{!0}
!air.language_version = !{!1}
!air.fragment = !{!2}
!0 = !{i32 2, i32 9, i32 0}
!1 = !{!"Metal", i32 4, i32 1, i32 0}
!2 = !{ptr @duo_sampler_bias_fragment, !3, !5}
!3 = !{!4}
!4 = !{!"air.render_target", i32 0, i32 0, !"air.arg_type_name", !"float4", !"air.arg_name", !"out"}
!5 = !{!6}
!6 = !{i32 0, !"air.texture", !"air.location_index", i32 0, i32 1, !"air.sample", !"air.arg_type_name", !"texture2d<float, sample>", !"air.arg_name", !"texture"}
