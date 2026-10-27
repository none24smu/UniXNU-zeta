#!/usr/bin/env python3
"""Prepare an isolated pinned AIR compiler candidate; never edit the donor checkout."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
EXPECTED = {
    "air_to_nir.c": "56b45563792db03700c275e3440260bf7e97720cbd69fbbf6337f9a698d160f4",
    "air_intrinsics.c": "f5f06bfa01f100acb044bde9c6ea58149a889484505ed308a3a9cc511eb23910",
}


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("AIR source context differs from expected pinned donor")
    return source.replace(old, new)


def prepare(source, output):
    source, output = source.resolve(), output.resolve()
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("candidate must be separate from source tree")
    output.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in source.iterdir() if path.is_file() and path.suffix in (".c", ".h"))
    inputs = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    if any(inputs.get(name) != digest for name, digest in EXPECTED.items()):
        raise ValueError("AIR compiler critical source SHA-256 differs from pinned donor")
    for path in files:
        shutil.copyfile(path, output / path.name)
    shutil.copyfile(ROOT / "compiler/duo_air_sampler.h", output / "duo_air_sampler.h")
    for name in ("duo_air_backend.h", "duo_air_backend.c"):
        shutil.copyfile(ROOT / "compiler" / name, output / name)
    patches = []
    path = output / "air_to_nir.c"
    original = path.read_text()
    text = replace_once(original, '#include "air_private.h"', '#include "air_private.h"\n#include "duo_air_sampler.h"')
    old = '''         if (g->init && !air_const_uint(g->init, &word)) {
            air_error(c, "interface: an inline sampler whose state is not a constant");
            return;
         }'''
    new = '''         if (g->init) {
            enum duo_air_sampler_result result = duo_air_sampler_word(g->init, &word);
            if (result != DUO_AIR_SAMPLER_OK) {
               air_error(c, result == DUO_AIR_SAMPLER_SECOND_WORD_UNSUPPORTED
                  ? "interface: inline sampler has a nonzero second word (LOD bias/extensions unsupported)"
                  : "interface: inline sampler initializer is not a supported constant i64 or [2 x i64]");
               return;
            }
         }'''
    text = replace_once(text, old, new)
    path.write_text(text)
    patches.extend(difflib.unified_diff(original.splitlines(True), text.splitlines(True), "a/air_to_nir.c", "b/air_to_nir.c"))
    path = output / "air_intrinsics.c"
    original = path.read_text()
    anchor = '''   if (!strncmp(name, "llvm.memcpy.", 12)) {'''
    arithmetic = '''   /* LLVM unsigned maximum and saturating subtraction. These are scalar
    * i32/i64 forms present in actual AIR 2.9; no signed arithmetic or wrapping
    * subtraction can stand in for them. NIR owns backend lowering. */
   bool unsigned_max = !strcmp(name, "llvm.umax.i32") || !strcmp(name, "llvm.umax.i64");
   bool unsigned_sub_sat = !strcmp(name, "llvm.usub.sat.i32") || !strcmp(name, "llvm.usub.sat.i64");
   if (unsigned_max || unsigned_sub_sat) {
      unsigned width = strstr(name, ".i64") ? 64 : 32;
      if (in->num_operands != 3 || in->base.type->kind != AIR_TYPE_INT || in->base.type->bits != width ||
          in->operands[1]->type->kind != AIR_TYPE_INT || in->operands[1]->type->bits != width ||
          in->operands[2]->type->kind != AIR_TYPE_INT || in->operands[2]->type->bits != width)
         return air_error(c, "intrinsic: malformed unsigned min/max/saturation signature");
      nir_def *a = air_get_ssa(c, in->operands[1]);
      nir_def *b = air_get_ssa(c, in->operands[2]);
      if (!a || !b) return false;
      air_set(c, &in->base, air_val_ssa(c, unsigned_max ? nir_umax(&c->b, a, b) : nir_usub_sat(&c->b, a, b)));
      return true;
   }
'''
    text = replace_once(original, anchor, arithmetic + anchor)
    path.write_text(text)
    patches.extend(difflib.unified_diff(original.splitlines(True), text.splitlines(True), "a/air_intrinsics.c", "b/air_intrinsics.c"))
    (output / "duo-air.patch").write_text("".join(patches))
    (output / "duo-air-inputs.json").write_text(json.dumps({
        "donor_revision": "3278f7f01796e74ecd634c0d348d2b255a37658f", "input_sha256": inputs,
        "candidate_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in output.glob("*.[ch]")},
        "scope": "constant sampler representation and scalar LLVM unsigned arithmetic; no shader execution"}, indent=2) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    prepare(a.source, a.output)
