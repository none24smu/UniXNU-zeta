# Experimental iOS 27 x1 CPU and loader conversion

The iPhone19,4 / 24A94425 launchd, dyld and SystemOS cache require more than stripping pointer authentication. Their original code includes FEAT_PAuth_LR, pointer arithmetic from CPA/CPA2 and scalar CSSC instructions. The default converters still reject arm64e.x1. A separate `sm8350-x1-experimental-v1` profile can plan exact edits, but cannot emit executables with a draft kernel contract.

## Read-only plans

`rewrite-zeta-userland.py --plan-only --input IMAGE --apple-trust-cache ORIGINAL_TRUSTCACHE --report PLAN.json` verifies the original signature and Apple trust-cache membership, proves code, and records PAuth/PAuthLR plus CPTA-OFF ADDPT/SUBPT/MADDPT edits. It emits no executable or new trusted CDHash. Plan-only pointer lowering is a proposed compatibility policy, not proof that the running guest has that policy.

`prove-zeta-dyld-cache.py --experimental-x1-plan --cache CACHE --work OUTPUT --jobs 2` validates subcache UUIDs, mappings, slide-v5 geometry and code boundaries, then records an edit plan and remaining ISA requirements. `--only` makes a bounded diagnostic proof; it cannot qualify a cache rewrite. Original file and proof-tool hashes, per-image edit-array hashes and unresolved candidates are retained.

The x1 code proof recognizes exact TCHANGE instruction forms as fallthrough code without modifying their semantics. Detached executable selector thunks require the complete ADRP-X1 / ADD-X1 / B-to-owned-code / BRK pattern and an incoming proven branch. The pattern does not turn arbitrary cache mapping gaps into code. A section-ending call terminates a path only when its target is the exact exported `___assert_rtn` address or Darwin `__exit`/`___exit` (also bound to its actual syscall1 stub), or an exact executable forwarding thunk to those addresses; arbitrary calls still cannot justify falling outside instruction sections.

## Executable conversion gate

`--x1-contract` must identify a validated `zeta-x1-kernel-contract-v1` manifest. `zeta_x1_compat.load_contract` checks immutable kernel, source, helper and adapter artifacts; effective guest observations; and native EL0 evidence. Required policy includes ordinary-pointer ABI, no advertised PAuth/CPA2/MTE, explicit effective CPTA OFF, platform-task scoped opt-in CSSC support for all seven supported scalar operations, and a verified disabled hardware-TPRO path. CPTA OFF is a chosen compatibility policy: it does not retain Apple's CPTA-ON poison checks.

Platform-task CSSC qualification must use a signed probe with a basename distinct from `zeta-isa-probe`. The manifest verifies the probe's actual primary CodeDirectory CDHash and requires self `CS_OPS_STATUS` platform bit, self `CS_OPS_CDHASH`, exact kernel identity, a mode1 negative result and mode2 positive result for the same probe. Static trust-cache membership alone does not prove the process is platform signed; AMFI's signature-policy callback supplies that status. A mode1 probe-only pass cannot qualify launchd.

Retained TPRO, MTE, SHA512, RCPC2 and AMX words require either native execution evidence or exact-input-bound disabled-path evidence. They are not replaced with NOPs. Unknown instructions, code-boundary anomalies, unlowerable pointer forms and unproven candidates stop conversion. Cache rewriting additionally requires the complete image set and matching original/proof/tool hashes. The cache family retains its UUIDs, layout, slide chains and original-to-owner trust attributes; declared architecture headers and code signatures are updated only after qualification.

## Current limit

The working contract remains draft. No iOS 27 converted executable or cache has been issued by this profile, and no iOS 27 runtime success is claimed. Local read-only plans and diagnostics are under `../x1-conversion/` outside the board repository.

The CSSC trap helper is a compatibility fallback, not a 60/90 Hz performance result. A hot CTZ can need RBIT+CLZ with a relocated second instruction; general min/max needs comparison/selection and often flags preservation. Future AOT sequences therefore require relocation, register-liveness and NZCV proofs. Some exact special cases can fit one word (for example UMIN-immediate0 to MOVZ, UMAX-immediate0 to MOV), but this profile does not yet emit them. Instruction-site counts do not measure runtime trap frequency or frame time.
