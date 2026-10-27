# Dropped multisample resolve target

The current Metal frontend drops `MTLRenderPassAttachmentDescriptor.resolveTexture`,
`resolveLevel`, `resolveSlice` and `resolveDepthPlane`. Its C attachment structure
cannot represent them, and the Rust bridge leaves the runtime resolve target at
`None`. A color pass using `MultisampleResolve` without a target succeeds while
resolving nowhere. Its multisample attachment may be discarded; the intended
single-sample destination stays unchanged.

This omission is confirmed in the running plugin's dSYM: `NmbPassAttachment` has
size 0x50 and no resolve fields. The running artifact has SHA256
`c034715a408df4c44af7ae817307bba2637900721c7c6435b070f722b62f3ba1`.
Mercury's process-specific Space pipelines use four samples. The matching stock
MetalKit `MTKView.configureColorAttachments:` sets a separate resolve texture
and store action 2 when sampleCount exceeds one. Read-only cached and uncached
DRAM samples of Mercury's imported surfaces and large private GPU allocations
were zero at the sampled locations. Those samples alone do not establish every
pixel or identify each private allocation's texture type.

The patch forwards each attachment's resolve texture and subresource through
both C ABI definitions into the existing runtime resolve implementation. It
retains resolve texture owners until GPU completion and includes their
IOSurfaces in cache maintenance. A bounded per-process render-pass journal
records actual samples, store action and resolve target for hardware validation.
No change to the shader translator, GPU firmware, kernel or device profile is
needed for this correction.

The regression uses clear-only four-sample passes, without shader compilation.
It checks that an unsupported multisampled resolve destination reaches runtime
validation. Valid passes cover both resolve store actions and a nonzero
resolve mip/slice. The old-code control drops only resolve transport and must
incorrectly accept the unsupported destination. Optional `--pixels` requires an
executing Vulkan backend and checks all 64 red output pixels; the software
kernel peer does not establish rendered pixels.

This branch starts at 02b79c2 (the control graphics profile) and excludes the
unfinished render linked-function candidate. Patch application, Python syntax
and whitespace checks were performed. No compilation, CI run, deployment or
wallpaper repair is claimed yet: builds remain stopped under the user's
instruction until the targeted plugin build is authorized. Hardware acceptance
requires process-specific render-pass evidence and a visible wallpaper in the
current OS session. No OS reboot is authorized for this test.

Local evidence is retained in work/render-stage7/wallpaper-linked1:
- metalkit-msaa-resolve-rea.json, evidence ev_e869e7130a341fb82bbd3f2c055a5a42c71748d36872403a7fe46f3a7470676d
- mercury-gpu-dram-samples.json and gpu-read-controls.json
- current-recheck-frames/frame-8.png
