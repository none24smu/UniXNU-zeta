# Vulkan pass encoding and completion ownership

`src/vulkan_pass.cpp` uses the core Vulkan 1.0 render-pass/framebuffer API and real
Khronos structs/function-pointer types. Production must populate `VulkanDispatch`
from the actual device dispatch and supply real handles. Tests inject a capture
dispatch; they create no device and execute no GPU instructions. There is no
software fallback and no silent format conversion.

`queryVulkanAttachmentCapabilities` queries the real physical framebuffer limits
and optimal-tiling 2D attachment format properties, intersecting supported sample
counts with the physical framebuffer sample masks. It skips unsupported formats
and reports query errors. Supported mappings are R8, RGBA8/BGRA8 UNORM and sRGB,
RGBA16Float, and Depth32Float. Combined depth/stencil and depth resolve remain
explicitly unsupported. This function is not evidence of an actual A660 query in
this change: the host test uses a capture physical-device implementation.

## Binding and state preconditions

Create a `VulkanDevice` with a real graphics queue family, retained device owner,
queried capabilities and full dispatch. Each `VulkanImageBinding` must describe
the actual image creation, including format, dimensions, mip/layer counts,
sample count and usage. Its owner must keep both the VkImage and its bound memory
alive. The encoder rejects missing owners, duplicate native images, metadata
differences and missing attachment usage. It reconstructs a canonical resource
list from validated attachments rather than trusting mutable public plan data.

Supply exactly one `VulkanViewState` per selected attachment/resolve subresource.
`before` must be the state established by previously ordered work on this queue;
`after` is the requested next state. Layout, stage/access compatibility and
layout-dependent usage are checked for the bounded supported state vocabulary.
For `LOAD`, the caller must additionally guarantee valid previous image content;
the encoder rejects an undefined starting layout. Storing an attachment preserves
produced contents but does not prove all pixels were written. Partial draws after
a discard do not make untouched pixels defined.

All before/after states must already belong to the encoder's queue family.
Cross-queue, external/foreign and display ownership transfers are rejected.
Perform the required semaphore waits and paired external acquire/release outside
this encoder, update the authoritative state, and only then encode. The encoder
does not manufacture ownership or CPU cache coherency from a layout enum.

Barriers select exactly one mip and one array slice. They transition each view to
COLOR_ATTACHMENT_OPTIMAL or DEPTH_STENCIL_ATTACHMENT_OPTIMAL, make preceding
accesses visible to attachment read/write operations, then transition to the
requested after state following `vkCmdEndRenderPass`. The render pass uses those
same attachment layouts for initial/final state. It does not hide an additional
undefined-layout transition. Source/resolve views have identity swizzles and a
single mip/layer; framebuffer and render area use the planner's selected mip
extent. Sparse color indices remain shader output locations.

Resolve destinations are always independent render-pass attachments with
single-sample storage, DONT_CARE load and STORE. Their subpass references survive
when the MSAA source uses DONT_CARE store. Store-and-resolve changes only source
storage; it never suppresses the resolve attachment.

## Recording and handoff

`encodeVulkanPass` creates and owns the views, render pass and framebuffer. Failed
creation cleans only successfully created objects. `begin(commandBuffer)` records
the before barriers and `vkCmdBeginRenderPass`; record compatible Vulkan draw
commands, then call `end` on the same command buffer to record end/after barriers.
The pass is one-shot. The command buffer must be a recording primary buffer,
outside another render pass, allocated for the supplied graphics family. The
caller remains responsible for compatible pipelines, viewport/scissor, descriptors,
full shader-resource residency and command-buffer lifecycle.

Before calling `vkQueueSubmit`, reserve ownership:

```cpp
auto encoded = encodeVulkanPass(plan, device, bindings, states);
// Check encoded, record begin/draws/end, then end the command buffer.
auto error = completions.prepareSubmission(encoded.pass, fence, fenceOwner);
// Abort submission if error is nonempty. Preparation allocates before GPU work exists.
// The real unsignaled VkFence must cover this pass's command buffer.
VkResult result = vkQueueSubmit(queue, 1, &submitInfo, fence);
if (result == VK_SUCCESS) {
    error = completions.confirmSubmitted(encoded.pass); // Success path does not allocate.
}
```

Keep the command buffer and command pool alive in the surrounding submission
owner as well. This completion queue owns the pass and fence only. To reserve
multiple passes for one submission, prepare each before submission and confirm
each after success; cancel all reservations if the submit call is never made.

`cancelUnsubmitted` releases only a reservation for which **no** GPU submission
occurred. Never cancel uncertain or device-lost submissions. A failed queue call
requires the surrounding queue/device recovery policy to establish execution
state; this small component does not implement device-loss recovery. A reserved
pass is not polled or retired until confirmed, so a previously signaled fence
cannot prematurely release objects before the submit call.

After successful handoff, callers may release their descriptor, image bindings,
pass and fence references. `pollCompleted` retains objects on VK_NOT_READY and on
all driver errors. Only VK_SUCCESS from `vkGetFenceStatus` retires submitted
ownership. Do not reset/reuse a submission fence until all its passes retire.
The device and native image owners survive until framebuffer/render-pass/views
have been destroyed. Discarding an unsubmitted recorded pass invalidates commands
that refer to its framebuffer; reset/discard that command buffer before reuse.

The completion queue must outlive all pending or reserved work. Destroying a
nonempty queue terminates as a programming error rather than freeing resources
that the GPU may still reference. Queue access, image-state tracking, command
recording and Vulkan object destruction must be externally synchronized. No
implicit wait, global device idle or forced GPU completion is introduced.

## Required physical validation

This implementation still needs an actual Turnip device, correctly created/bound
images and GPU fence integration. First run exact GPU clear/resolve/readback
through these functions with 2x/4x MSAA, source discard, nonzero resolve mip/slice,
store-and-resolve and in-flight caller release. Check Vulkan validation output,
pixel bytes, real GPU-written completion and MMU faults. Follow with triangle,
blend/sRGB, depth and actual compositor shader passes. Host capture success does
not replace any of those physical gates.

Primary API references used for the implementation:
[attachment descriptions](https://docs.vulkan.org/refpages/latest/refpages/source/VkAttachmentDescription.html),
[subpass color/resolve references](https://docs.vulkan.org/refpages/latest/refpages/source/VkSubpassDescription.html),
[image barriers and ownership](https://docs.vulkan.org/refpages/latest/refpages/source/VkImageMemoryBarrier.html),
[framebuffer requirements](https://docs.vulkan.org/refpages/latest/refpages/source/VkFramebufferCreateInfo.html),
[framebuffer destruction lifetime](https://docs.vulkan.org/refpages/latest/refpages/source/vkDestroyFramebuffer.html),
and [fence status](https://docs.vulkan.org/refpages/latest/refpages/source/vkGetFenceStatus.html).
