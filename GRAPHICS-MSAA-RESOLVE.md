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
unfinished render linked-function candidate. The targeted plugin build was
authorized by the user's instruction to perform the live test. GitHub Actions
run 40491995063 at 12b7794346dff6acce9bd35cf36d9857cf04a3f6 passed the build,
regression and old-code negative control. The earlier test also exposed an
Apple encoder cleanup assertion on descriptor rejection; validation now occurs
before allocating that encoder.

On 2026-10-27 the candidate was tested in the existing running OS, without an
OS reboot or boot-image build. Its executable was staged under a separate name
and verified against a complete USB readback, with SHA256
15756331f15708eeba938d988b065aac741ba7fddf1ab7bb991229efe5332dba.
The ad hoc signature was resealed for that staging name and the retained existing
bundle resources. Its hash was admitted into the running development trust
cache without removing existing entries. Original bundle metadata and the old
executable remain available for rollback. Only MercuryPosterExtension was
restarted, with its closed diagnostic connection budget refilled by two grants;
no concurrency or resource ownership guard was relaxed.

PID14755 loaded NativeAdrenoMetal.msaa, confirmed from its current dyld image
list. Its process-specific pass journal records four-sample color attachments,
store action 2 and non-null resolve destinations at both 1377x946 and 2754x1892.
No texture refusals or command commit failures were reported in the first
counter read. The observed 3 commits / 2 callback completions coincided with
RunningBoard suspension; it is not evidence of a hung GPU.

A fresh USB scanout shows blue wallpaper shapes where the control scanout was
black, and the user independently reported seeing parts of the wallpaper.
This verifies the missing resolve transport as a cause of missing wallpaper
content. It does not establish full visual correctness, the lock screen, or a
performance repair. Black regions and remaining appearance need further
comparison before calling the complete rendering issue fixed.

Live evidence is retained in work/render-stage7/msaa-live: stage-manifest.json,
upload-verified.json, activation.json, wallpaper-restart.json, observation-first.json,
new-pipelines.log and frames/frame-8.png. The USB decoder was adjusted to accept
complete concatenated snapshot records: IOLog can omit a trailing newline.
Offsets, lengths, RLE size and unchanged drop counts still validate the frame.

Local evidence is retained in work/render-stage7/wallpaper-linked1:
- metalkit-msaa-resolve-rea.json, evidence ev_e869e7130a341fb82bbd3f2c055a5a42c71748d36872403a7fe46f3a7470676d
- mercury-gpu-dram-samples.json and gpu-read-controls.json
- current-recheck-frames/frame-8.png
