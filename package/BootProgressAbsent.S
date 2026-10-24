/*
 * The sheng drivers BootProgress.c reads but zeta does not build yet (virtio block, legacy display, Adreno, touch,
 * HID, log). BootProgress.c declares them weak_import and skips a row when the
 * address is null; the kernel is a static link, so each data symbol is an absolute symbol at 0 (as UniXNU links
 * absolute bindings, scripts/data/native-aes-original-bindings.S). Remove a name when its zeta driver lands: the
 * link reports a duplicate symbol. The functions are called with a direct bl, which cannot reach address 0, so they
 * are weak definitions that do nothing and return 0 rows; a driver's own definition replaces them.
 */
.globl _native_adreno_audit_attr
.set _native_adreno_audit_attr, 0
.globl _native_adreno_audit_ticks
.set _native_adreno_audit_ticks, 0
.globl _native_adreno_cache_stats
.set _native_adreno_cache_stats, 0
.globl _native_adreno_coherence
.set _native_adreno_coherence, 0
.globl _native_adreno_reassert_ticks
.set _native_adreno_reassert_ticks, 0
.globl _native_adreno_wc_audit
.set _native_adreno_wc_audit, 0
.globl _native_adreno_wc_distrusted
.set _native_adreno_wc_distrusted, 0
.globl _native_gop_gpu_abandoned
.set _native_gop_gpu_abandoned, 0
.globl _native_gop_gpu_completions
.set _native_gop_gpu_completions, 0
.globl _native_gop_gpu_failures
.set _native_gop_gpu_failures, 0
.globl _native_gop_gpu_offers
.set _native_gop_gpu_offers, 0
.globl _native_hid_input_events
.set _native_hid_input_events, 0
.globl _native_hid_input_results
.set _native_hid_input_results, 0
.globl _native_legacy_client_calls
.set _native_legacy_client_calls, 0
.globl _native_legacy_client_class
.set _native_legacy_client_class, 0
.globl _native_legacy_client_pid
.set _native_legacy_client_pid, 0
.globl _native_legacy_client_status
.set _native_legacy_client_status, 0
.globl _native_legacy_client_type
.set _native_legacy_client_type, 0
.globl _native_legacy_copy_bytes_last
.set _native_legacy_copy_bytes_last, 0
.globl _native_legacy_copy_bytes_sum
.set _native_legacy_copy_bytes_sum, 0
.globl _native_legacy_copy_last
.set _native_legacy_copy_last, 0
.globl _native_legacy_copy_max
.set _native_legacy_copy_max, 0
.globl _native_legacy_copy_n
.set _native_legacy_copy_n, 0
.globl _native_legacy_copy_sum
.set _native_legacy_copy_sum, 0
.globl _native_legacy_frame_color_counts
.set _native_legacy_frame_color_counts, 0
.globl _native_legacy_frame_color_other
.set _native_legacy_frame_color_other, 0
.globl _native_legacy_frame_colors
.set _native_legacy_frame_colors, 0
.globl _native_legacy_frame_count
.set _native_legacy_frame_count, 0
.globl _native_legacy_frame_kind
.set _native_legacy_frame_kind, 0
.globl _native_legacy_frame_stats
.set _native_legacy_frame_stats, 0
.globl _native_legacy_frame_time
.set _native_legacy_frame_time, 0
.globl _native_legacy_gop_bytes
.set _native_legacy_gop_bytes, 0
.globl _native_legacy_gop_physical
.set _native_legacy_gop_physical, 0
.globl _native_legacy_gop_virtual
.set _native_legacy_gop_virtual, 0
.globl _native_legacy_gpu_fallbacks
.set _native_legacy_gpu_fallbacks, 0
.globl _native_legacy_gpu_last_status
.set _native_legacy_gpu_last_status, 0
.globl _native_legacy_guard_slot
.set _native_legacy_guard_slot, 0
.globl _native_legacy_pm_callbacks
.set _native_legacy_pm_callbacks, 0
.globl _native_legacy_pm_calls
.set _native_legacy_pm_calls, 0
.globl _native_legacy_pm_stage
.set _native_legacy_pm_stage, 0
.globl _native_legacy_prepare_attempts
.set _native_legacy_prepare_attempts, 0
.globl _native_legacy_prepare_calls
.set _native_legacy_prepare_calls, 0
.globl _native_legacy_prepare_reason
.set _native_legacy_prepare_reason, 0
.globl _native_legacy_rej_class
.set _native_legacy_rej_class, 0
.globl _native_legacy_rej_reason
.set _native_legacy_rej_reason, 0
.globl _native_legacy_rej_size
.set _native_legacy_rej_size, 0
.globl _native_legacy_rej_state
.set _native_legacy_rej_state, 0
.globl _native_legacy_rej_surface
.set _native_legacy_rej_surface, 0
.globl _native_legacy_rej_surfaces
.set _native_legacy_rej_surfaces, 0
.globl _native_legacy_retirement_calls
.set _native_legacy_retirement_calls, 0
.globl _native_legacy_stage
.set _native_legacy_stage, 0
.globl _native_legacy_swap_accepted_count
.set _native_legacy_swap_accepted_count, 0
.globl _native_legacy_swap_rejected_count
.set _native_legacy_swap_rejected_count, 0
.globl _native_legacy_swap_validation_calls
.set _native_legacy_swap_validation_calls, 0
.globl _native_legacy_swap_validation_reason
.set _native_legacy_swap_validation_reason, 0
.globl _native_legacy_swap_validation_result
.set _native_legacy_swap_validation_result, 0
.globl _native_legacy_transfer_bytes
.set _native_legacy_transfer_bytes, 0
.globl _native_legacy_transfer_calls
.set _native_legacy_transfer_calls, 0
.globl _native_legacy_transfer_status
.set _native_legacy_transfer_status, 0
.globl _native_touch_count
.set _native_touch_count, 0
.globl _native_touch_rows
.set _native_touch_rows, 0
.globl _native_touch_seq
.set _native_touch_seq, 0
.globl _native_touch_stage_req
.set _native_touch_stage_req, 0
.globl _native_touch_xs
.set _native_touch_xs, 0
.globl _native_touch_ys
.set _native_touch_ys, 0
.globl _native_virtio_read_failures
.set _native_virtio_read_failures, 0
.globl _native_virtio_read_requests
.set _native_virtio_read_requests, 0
.globl _native_virtio_ready
.set _native_virtio_ready, 0
.globl _native_virtio_verified_blocks
.set _native_virtio_verified_blocks, 0
.globl _native_wi_count
.set _native_wi_count, 0
.globl _native_wi_log
.set _native_wi_log, 0

.text
.p2align 2
.globl _boot_log_tick
.weak_definition _boot_log_tick
_boot_log_tick:
	mov	w0, #0
	ret
