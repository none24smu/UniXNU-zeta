# Opt-in scalar user-instruction compatibility experiment

`ZetaUserInstructionCompat.c/.h` implements allocation-free register semantics.
The pure helper performs no code fetch, user-memory access, exception delivery
or PC update. The separate `ZetaUserInstructionKernel.c` adapter is included in
the owner-Data diagnostic archive; its runtime policy defaults to disabled. A successful call changes only the architectural destination; a
failure leaves the supplied state unchanged.

Supported exact scalar forms: UMIN/UMAX/SMIN/SMAX with register or imm8 operands,
CTZ, CNT and ABS, each in 32/64-bit form. W writes clear the upper X bits. ZR reads
return zero and ZR writes are discarded. CTZ(0) returns the operand width;
ABS(INT_MIN) retains that bit pattern. NZCV and the rest of PSTATE are preserved.
The pure state has x0..x30 and a separate SP; it is not XNU's saved-state layout.

ADDPT/SUBPT additionally require explicit UNKNOWN/OFF/ON effective-CPTA policy.
UNKNOWN or an invalid policy rejects the operation. MADDPT accepts only OFF, which also disables effective CPTM by architectural definition; ON needs a separate CPTM policy and is rejected. ON for ADDPT/SUBPT applies the architectural
poison check; OFF retains modulo-64-bit arithmetic. No inference from the host
CPU or a persona string selects a policy. The helper does not emulate CPA load/
store instrumentation, TPRO, MTE, PAC, or unrelated instructions.

## Exact single-word pointer lowering under explicit OFF

The planning API emits an ordinary nonflag ADD/SUB/MADD instruction only for explicit
CPTA OFF. With Rn/Rd other than 31 it uses shifted-register LSL #0..7. If either
is 31 it uses extended-register UXTX, whose shift must be 0..4; larger shifts are
rejected. This preserves the distinction between SP and ZR. MADDPT lowers to ordinary MADD with the same registers; every31 field is ZR. Output is unchanged
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
passes 124272 host mathematical-oracle cases, 200000 address/undefined-behavior
sanitizer iterations, 300 CSSC LLVM assembler encoding cases, 288 exact OFF
lowering LLVM encoding cases, and 75264 AArch64 differential cases. Pointer ON
edge cases include existing poison, top-byte changes, wrapping arithmetic and
all shifts. UNKNOWN/OFF/ON and invalid policies, register aliasing, SP/ZR,
reserved encodings, zero operands and signed boundaries are covered.

Available QEMU 8.2/10.1 do not implement scalar CSSC. The differential test uses
independent LLVM-assembled baseline CSSC reference sequences with explicit NZCV
preservation, and executes the actual emitted ordinary ADD/SUB words for pointer
lowerings. It does not claim native CSSC execution, XNU trap validation, or
physical SM8350 timing, or data-independent-timing guarantees. The existing proven-word audit has 1168 dyld and 62 launchd
pointer sites that fit the single-word OFF planner; OFF is not yet qualified.

## XNU adapter and qualification boundary

The root patch `native-zeta-user-cssc.patch` adds a callback only inside
XNU12377's existing uncategorized exception handler, behind the explicit
`XNU_ZETA_USER_CSSC=1` final-build flag. The bootstrap pass undefines that
flag until the provider archive exists. The callback then links strongly, so a
missing provider fails the build. It retains the initial
COPYIN result, skips the callback on failure, and preserves kernel, debugger,
DTrace and AArch32 handling. The adapter checks64-bit EL0/aligned PC and performs
a second checked4-byte copyin. Changed/failed fetches and unsupported instructions
leave state untouched and continue through XNU's normal exception delivery.

The adapter maps x0..x28 through saved-state accessors, FP/LR separately, and uses
signed user-state setters for x16/x17/LR/PC. It commits only the destination and
advances PC exactly4bytes. It passes CPTA UNKNOWN, so ADDPT/SUBPT/MADDPT are
**never** handled by this trap path. `zeta-cssc-compat=0` disables it (default),
`1` permits only the diagnostic basename `zeta-isa-probe`, and `2` additionally
permits platform binaries as determined by XNU's actual code-signing state.
Mode2 is an experiment, not a qualified product setting. The exported mode word
and eight counters support owner diagnostics; no per-trap log or allocation is
performed. Matching a basename is a diagnostic convenience, not code identity.

```
python3 scripts/check-zeta-instruction-kernel.py --output <fresh-output>
```

The actual adapter passes2133 host ASan/UBSan cases with the actual signed64-bit `register_t` ABI against mocked XNU accessors:
mode/process gates, failed/changed fetches, kernel/AArch32 rejection, exact state
and PC preservation, W zero extension, FP/LR/x16/x17/ZR, high-bit register preservation, pointer refusal and
unsupported opcodes. These are host tests, not native ABI or exception proof.
The first native kernel build and EL0 experiment are pending. Execute-permission
and writable-code races are not generally qualified: the current limited target
is signed immutable text; double fetching does not solve arbitrary JIT races.

The baseline-arm64 `experimental/isa-compat` probe contains32 independently
LLVM-checked CSSC encodings with nine edge values each, preserves/tests NZCV,
uses signal recovery for missing features, and records native csops platform
status/CDHash. Separate same-CDHash basenames allow mode1-denied/mode2-allowed
validation without broadening the adapter. Additional guest probes cover
ADDPT/MADDPT, LDAPUR, IRG, SHA512, paired pointer authentication, an unallocated
negative control and TPRO commpage state. It does not execute TCHANGE or EL1
register accesses. Native outcomes must be bound to the exact tested kernel and
probe files before the converter's explicit x1 contract can become validated.

Source searches found no CPTA/CPA2 task-policy implementation in the inspected
XNU arm/arm64/BSD-kern paths. Reference-task CPTA policy and the replacement
kernel's chosen ABI remain distinct. Feature/persona spoofing is not proof.

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
pages 16, 24, 337, 540, 692-693, 695-696, 826, 874-877, 4522-4523 and 4623 as relevant;
encoding cross-check: [LLVM AArch64 definitions](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64InstrInfo.td)
and [formats](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64InstrFormats.td).
Exact downloaded-document and code hashes, logs, masks and the read-only site
plan are retained under `work/ios27-port/isa-compat/`.
