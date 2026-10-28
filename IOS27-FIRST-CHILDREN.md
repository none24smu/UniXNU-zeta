# Original iOS27 first-child executable checkpoint

Eight original24A94425 executables are retained under `../x1-conversion/first-child-executables1/originals/`. Each hash matches the complete stock inventory and original Apple trust-cache membership. Plans are read-only: no rewritten iOS executable, root staging edit, kernel build or phone operation was performed.

| Program | Original file bytes | `__text` bytes | Proven pointer edits | Retained ISA after those edits |
| --- | ---: | ---: | ---: | --- |
| xpcproxy | 133600 | 39492 | 433 | None found in its own proven code |
| backboardd | 801456 | 356072 | 5137 | None found |
| SpringBoard | 140448 | 4 | 1 | None found |
| notifyd | 129344 | 45612 | 449 | None found |
| logd | 304256 | 159980 | 2014 | 14 CSSC |
| runningboardd | 74480 | 64 | 6 | None found |
| lsd | 58496 | 4 | 1 | None found |
| securityd | 4133632 | 2515748 | 22908 | 32 CSSC |

All eight headers are subtype`0x8000000c`: masked subtype12, masked features`0x80000000`. The standalone plans have zero boundary anomalies. Independent readback checked all30949 planned source words and exact selector outputs. These results exclude each program's imported framework/cache implementations, syscall semantics and runtime initialization.

xpcproxy contains real launcher/setup code rather than a four-byte framework trampoline, but its own39KiB text has a bounded pointer-only conversion plan. Its declared dependencies are libSystem and libobjc. The original LC_MAIN entry is VA`0x100000940`, file offset2368, with unsupported PACIBSPPC word`0xdac1a7fe` immediately at entry. A runtime capture still needs its actual image mapping/slide and process identity. Original CodeDirectory flags are`0x10002` (including runtime), platform identifier0; the source remains unchanged.

SpringBoard and lsd each branch from their four-byte text to an authenticated import stub; each needs one proven BRAA lowering there. Their implementations reside in imported frameworks. Runningboardd similarly has64 bytes of text and six pointer edits. Admitting their original headers alone leaves those instruction boundaries intact.

## Exact XNU12377 architecture-grade override

The unmodified source checkout is tag`xnu-12377.121.6`, revision`ac9718fb1af618d5ce8678d0dc6e8a58f252216f`. Its ARM64 V8 `ml_grade_binary()` has no subtype12 case and returns0 for these headers. `load_machfile()` passes the low subtype and the high feature bits separately to grading, using mask`0xff000000`.

The verified exact-feature diagnostic argument is:

```text
bingrade=0x100000c:0x0000000c:0x80000000
```

The two-field wildcard alternative is `bingrade=0x100000c:0xc`. Omitting the feature field matches any feature bits for that exact type/subtype. Up to four comma-separated tuples are supported; the first match receives grade200 and subsequent entries199,198,197. Overrides are compiled only with DEVELOPMENT or DEBUG. The retained e071 diagnostic kernel contains the parser/grading symbols.

The subtype padding in the three-field form is required by this exact source's parser bug. When the third field exists, it uses the subtype substring length as the destination size while copying the CPU-type text. The apparently natural `0x100000c:0xc:0x80000000` truncates the CPU type to`0x`, stores CPU type0 and does not match ARM64. The padded form above preserves the complete CPU type. Supplying full-header subtype`0x8000000c` also fails to match the masked subtype12. These are executed-source observations: the retained host harness compiles the actual parser, override matcher and ARM64 grading functions, then checks exact-feature success, wildcard behavior, both failing forms, ordered overrides and native no-override grades0/9/10 for x1/ALL/V8.

This override changes architecture admission only. Pointer instructions, signature/platform policy, imported-cache behavior and kernel APIs remain separate execution boundaries. No override was staged or applied during this audit.

Evidence: summary.json and per-program plans; independent-plan-readback.json; bingrade-host/result.json, result.log and extracted test source; exact kernel source snapshots under kernel-source/. All are beneath `../x1-conversion/first-child-executables1/`.

## Optional signed-page profile for these eight originals

The separate, default-off `XNU_IOS27_TEXT_FIXUPS=1` kernel source profile reads `/chosen/text-fixups-ios27`. It supports at most 32768 descriptors across 64 basenames and preserves the original 32-entry `/chosen/text-fixups` and boot arguments. The build flag affects only `bsd/DEVELOPMENT/ubc_subr.o`; changing it invalidates that object. No checked-in payload or profile selects this option.

Generate the exact table without rewriting the original files:

```sh
python3 scripts/generate-zeta-ios27-text-fixups.py \
  --child-checkpoint ../x1-conversion/first-child-executables1 \
  --output /new/output/directory
```

The generator pins all eight original SHA256 hashes and the eight reviewed plan hashes, verifies the original signed pages/CDHashes, checks each known lowering, and groups adjacent edits within 16 bytes and one 4KiB page. The retained output has 30949 instruction edits in 28208 descriptors, 1008132 ADT bytes, SHA256 `49bc5d3a26366fef7ed34685e0f3a51bba4000968ce47d2d4278b763682f2a86`. Pass the generated binary explicitly to the ordinary ADT generator with `--ios27-text-fixups PATH`. The architecture argument remains the padded, verified `bingrade=0x100000c:0x0000000c:0x80000000` above.

The kernel rejects the whole new table on malformed records, sorting errors, overlaps, overflow, excess capacity or conflicts with legacy entries. Runtime lookup uses a binary filename index and a binary offset search. It changes a page only after original signature validation succeeds without taint and all new-profile original-byte checks on that page pass. A mismatch leaves that page's new-profile bytes untouched. The runtime identity guard is basename plus a validated original signed page and exact bytes; the manifest's whole-file SHA256/CDHash is retained generation evidence, not a fault-path whole-file identity lookup.

Evidence under `../x1-conversion/signed-text-fixups1/`: `descriptors2/manifest.json`; `host3/result.json` and production C/VM-hook snapshots; build-flag tests; Python format tests; and a host-only ADT serialization/readback. The extracted production validator passes ASan/UBSan in both compile modes, including all 28208 descriptors on 810 original pages, legacy coexistence, rejection/atomicity and index bounds. These host checks do not qualify the actual kernel object or VM lifecycle. SDK compilation and a separately selected native diagnostic boot remain required. The 46 retained CSSC instructions remain unchanged; imported frameworks and unsupported cache instructions retain their separate compatibility gates.
