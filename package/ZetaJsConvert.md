# FJCVTZS compatibility helper

`ZetaJsConvert.c` implements the integer result, replacement NZCV field and
cumulative FPSR changes using integer operations on the binary64 source bits.
It does not access a thread's floating-point context, advance PC, install an
exception handler or advertise JSCVT. It is not selected in a phone image.

The supported control domain is FPCR.FZ=0, exception traps disabled and alternate
FP behavior disabled. Ordinary rounding-mode, DN, AHP and FZ16 bits are accepted;
they do not change this binary64 round-toward-zero conversion. Unsupported
controls and null output pointers refuse without changing output. XNU12377's
64-bit `FPCR_DEFAULT` is zero; applications can still change their FPCR.

The implementation follows the instruction and FPToFixedJS semantics in the
[Arm A64 specification](https://documentation-service.arm.com/static/68da52dfbd7cab51328c0622)
(2025-09 release). Negative zero clears Z; an out-of-range finite conversion
returns the low32bits and raises Invalid rather than saturating; fractional
in-range conversion raises Inexact. Existing cumulative FPSR flags do not
determine this instruction's new Z value.

Two independent execution oracles pass the same 2,058,752 comparisons over all
2048 exponent encodings, selected mantissa boundaries, both signs, eight
supported FPCR configurations, preexisting FPSR flags and random binary64
inputs. Each comparison checks the zero-extended result, full NZCV and FPSR.

* QEMU8.2.2 instruction model: local `isa-compat/js-convert-check3/result.json`.
* Actual Apple ARM64 instruction execution:
  [CI40581820453](https://github.com/none24smu/UniXNU-zeta/actions/runs/40581820453),
  source `8c0f1759ef65d6f80919578deb19b629822f4798`, retained under
  `isa-compat/js-native-qualified1`. This is host hardware, not the Duo guest.

The initial FZ=1 subnormal case disagreed with the newer Arm pseudocode in both
the installed older QEMU model and the available Apple host. The failed raw
results remain under `js-convert-check2` and `js-native-attempt1`. FZ=1 is
therefore explicitly refused; its semantics have not been qualified for the
target iPhone19,4 hardware. No oracle discrepancy is silently waived.

Remaining runtime integration: exact FJCVTZS decode, authoritative saved NEON
source/FPCR/FPSR access in the undefined-instruction path, lazy-state ownership,
destination/ZR and PSTATE updates, fault handling and actual signed-probe tests
on the Duo. Passing this pure helper does not close those gates or qualify the
complete iOS27 userspace.
