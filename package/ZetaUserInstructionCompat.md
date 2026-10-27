# Unwired scalar user-instruction compatibility helper

`ZetaUserInstructionCompat.c/.h` implements allocation-free register semantics.
It is deliberately absent from the kernel archives, trap patches and conversion
pipeline. No code fetch, user-memory access, exception delivery or PC update is
performed. A successful call changes only the architectural destination; a
failure leaves the supplied state unchanged.

Supported exact scalar forms: UMIN/UMAX/SMIN/SMAX with register or imm8 operands,
CTZ and ABS, each in 32/64-bit form. W writes clear the upper X bits. ZR reads
return zero and ZR writes are discarded. CTZ(0) returns the operand width;
ABS(INT_MIN) retains that bit pattern. NZCV and the rest of PSTATE are preserved.
The pure state has x0..x30 and a separate SP; it is not XNU's saved-state layout.

ADDPT/SUBPT additionally require explicit UNKNOWN/OFF/ON effective-CPTA policy.
UNKNOWN or an invalid policy rejects the operation. ON applies the architectural
poison check; OFF retains modulo-64-bit arithmetic. No inference from the host
CPU or a persona string selects a policy. The helper does not emulate CPA load/
store instrumentation, TPRO, MTE, PAC, or unrelated instructions.

## Exact single-word pointer lowering under explicit OFF

The planning API emits an ordinary nonflag ADD/SUB instruction only for explicit
CPTA OFF. With Rn/Rd other than 31 it uses shifted-register LSL #0..7. If either
is 31 it uses extended-register UXTX, whose shift must be 0..4; larger shifts are
rejected. This preserves the distinction between SP and ZR. Output is unchanged
on rejection. It neither writes executable memory nor changes the generic PAC
rewriter. CPTA ON cannot use this lowering because it would lose poison checks.

## Verification

```
python3 work/ios27-port/board/scripts/check-zeta-user-instruction-compat.py \
  --qemu work/tools/qemu-10.1/build/qemu-system-aarch64 \
  --output work/ios27-port/isa-compat/check
```

The actual source compiles as a freestanding plain ARM64/iOS26 object with
`-march=armv8-a -mgeneral-regs-only`; it imports no symbols. The current check
passes 93312 host mathematical-oracle cases, 200000 address/undefined-behavior
sanitizer iterations, 288 CSSC LLVM assembler encoding cases, 216 exact OFF
lowering LLVM encoding cases, and 64512 AArch64 differential cases. Pointer ON
edge cases include existing poison, top-byte changes, wrapping arithmetic and
all shifts. UNKNOWN/OFF/ON and invalid policies, register aliasing, SP/ZR,
reserved encodings, zero operands and signed boundaries are covered.

Available QEMU 8.2/10.1 do not implement scalar CSSC. The differential test uses
independent LLVM-assembled baseline CSSC reference sequences with explicit NZCV
preservation, and executes the actual emitted ordinary ADD/SUB words for pointer
lowerings. It does not claim native CSSC execution, XNU trap validation, or
physical SM8350 timing, or data-independent-timing guarantees. The existing proven-word audit has 1168 dyld and 62 launchd
pointer sites that fit the single-word OFF planner; OFF is not yet qualified.

## Required XNU adapter work before a runtime hook

The inspected XNU 12377 `osfmk/arm64/sleh.c` routes uncategorized synchronous
exceptions to `handle_uncategorized` (about line 1185). That function copies the
faulting word, recognizes debugger/DTrace cases, panics for undefined kernel
instructions, and otherwise delivers `EXC_BAD_INSTRUCTION/EXC_ARM_UNDEFINED`.
Its existing COPYIN result is ignored; an emulator must not reuse that as proof
that instruction fetch succeeded.

A future opt-in hook must:

1. Require a 64-bit EL0 saved state, the intended uncategorized ESR, aligned PC,
   and an explicitly enabled/task-scoped compatibility policy. Preserve kernel,
   AArch32, DTrace/debugger and unsupported-instruction behavior.
2. Safely fetch exactly 4 bytes with checked copyin, preserving normal user-fault
   recovery. A copy failure must not mutate registers/PC, retry indefinitely,
   or invent a successfully fetched word. Validate mappings/execute semantics
   and races with writable code rather than assuming successful data copyin
   proves executable ownership.
3. Map x0..x28 with user saved-state accessors, x29 through FP, x30 through LR,
   and SP separately. XNU's `arm_saved_state64` contains x[29], not x[31]. Use
   `set_user_saved_state_reg`/`set_user_saved_state_lr` and the proper FP/SP
   accessors, preserving signed-state/jophash handling where applicable.
4. Evaluate without committing, validate the destination and successful return,
   then commit exactly the destination and advance the user PC by 4 once via
   `add_user_saved_state_pc`. Preserve CPSR/NZCV and exception state. Confirm
   this in real EL0 tests including x16/x17/FP/LR/SP/ZR and a page-boundary fetch.
5. Provide bounded per-task/instruction counters and a way to disable fallback;
   validate unmapped/unreadable PC, unsupported opcodes, bad policy, signal and
   debugger interaction before enabling the hook.

A native compiler object is not this integration proof. Current source searches
found no CPTA/CPA2 task-policy implementation in the inspected XNU arm/arm64/
BSD-kern paths. Actual CPU advertisements, effective reference-task CPTA policy,
and the replacement kernel's policy still require explicit validation before
OFF can qualify an executable conversion. Feature/persona spoofing is not proof.

## Performance decision

No physical trap latency has been measured. Each trapped scalar instruction
would pay EL0 exception entry/return, saved-state handling, checked instruction
fetch, decode, and register commit. The helper's integer arithmetic is a small
part of that cost. For budgeting only:

| Assumed total cost per trap | 100000 traps/second consumes |
| --- | --- |
| 1 microsecond | 10% of one core |
| 5 microseconds | 50% of one core |
| 10 microseconds | 100% of one core |

These are scenarios, not latency estimates or benchmarks. Static instruction
counts do not establish their dynamic execution frequency. Count and measure
before selecting a default. Hot pointer arithmetic makes permanent per-op traps
a poor performance strategy; a qualified exact OFF AOT lowering avoids those
transitions. CSSC AOT expansion needs independent scratch-register, code-size,
branch/literal relocation and flag-liveness proof, rather than blindly inserting
CMP/CSEL (which changes NZCV).

Primary semantic source: [Arm A64 ISA 2025-09, including shared pseudocode](https://documentation-service.arm.com/static/68da52dfbd7cab51328c0622),
pages 16, 24, 337, 692-693, 695-696, 826, 874-877, 4522-4523 and 4623 as relevant;
encoding cross-check: [LLVM AArch64 definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64InstrInfo.td)
and [formats](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64InstrFormats.td).
Exact downloaded-document and code hashes, logs, masks and the read-only site
plan are retained under `work/ios27-port/isa-compat/`.
