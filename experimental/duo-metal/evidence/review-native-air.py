#!/usr/bin/env python3
"""Review retained host/device records; never connects to a device."""
import argparse
import datetime
import hashlib
import json
import struct
from pathlib import Path


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def kernel_span(path, proof):
    """Read the recorded VA from an exact thin 64-bit ARM Mach-O candidate."""
    raw = path.read_bytes()
    require(raw[:8] == bytes.fromhex("cffaedfe0c000001"), "not ARM64 Mach-O")
    va, length = int(proof["va"], 16), proof["matched_bytes"]
    require(length == 128, "unexpected runtime span length")
    offset = 32
    for _ in range(struct.unpack_from("<I", raw, 16)[0]):
        command, size = struct.unpack_from("<II", raw, offset)
        require(size >= 8 and offset + size <= len(raw), "bad Mach-O command")
        if command == 0x19:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", raw, offset + 24)
            if vmaddr <= va and va - vmaddr + length <= filesize:
                start = fileoff + va - vmaddr
                span = raw[start:start + length]
                require(len(span) == length and hashlib.sha256(span).hexdigest() == proof["sha256"],
                        "kernel candidate does not match recorded runtime span")
                return dict(candidate_sha256=digest(path), matched_file_bytes=length,
                            whole_running_image_hash_proven=False)
        offset += size
    raise ValueError("runtime VA absent from kernel file-backed segments")


def review(result_path, log_path, kernel_path, artifacts, kernel_image=None):
    result = json.loads(result_path.read_text())
    build = json.loads((artifacts / "build.json").read_text())
    trust = json.loads((artifacts / "trust.json").read_text())
    all_events = [json.loads(line) for line in log_path.read_text().splitlines()
                  if line.startswith('{')]
    events = [event for event in all_events if event.get("probe") == "duo_air_shader"]
    require(events == result["events"], "raw AIR log and result events differ")
    require(len(events) == 7, "unexpected event count")
    require(result["passed"] is True and result["gate_opened"] is True,
            "physical gate did not pass")
    require(events[0] == dict(probe="duo_air_shader", event="device", name="FD660",
                             software_fallback=False, explicit_air_vertex=True,
                             native_metal_objc_used=False), "unexpected device policy")
    expected = [("air_triangle_rgba32f", True, 0),
                ("air_premultiplied_source_over_rgba32f", True, 0),
                ("air_srgb_rgba8", True, 1),
                ("air_two_word_sampler_zero_bias", True, 0),
                ("nonzero_sampler_extension_explicit_refusal", False, 0)]
    tests = events[1:-1]
    for test, (name, drawn, tolerance) in zip(tests, expected):
        require(test["event"] == "test" and test["name"] == name,
                "unexpected test order or identity")
        require(test["status"] == "pass" and test["mismatches"] == 0,
                "test failed or mismatched")
        require(test["gpu_draw_executed"] is drawn and
                test["compared_components"] == (4096 if drawn else 0) and
                test["code_tolerance"] == tolerance, "comparison scope changed")
        require(all(test[k] >= 0 for k in ("compile_us", "draw_wait_us", "read_us")),
                "invalid timings")
    require("nonzero second word" in tests[-1]["detail"], "missing refusal reason")
    require(events[-1] == result["terminal"] and events[-1]["passed"] == 5 and
            events[-1]["status"] == "pass", "unexpected terminal result")
    for key in ("gpu_faults_checked", "actual_compositor_shader_proven", "ui_frame_rate_proven"):
        require(events[-1][key] is False, "checkpoint scope changed: " + key)
    require(result["client_policy_restored"] is True, "client policy not restored")
    stopped = {(p["pid"], p["name"]) for p in result["stopped"]}
    resumed = {(p["pid"], p["name"]) for p in result["resumed"] if p["status"] == 0}
    require(stopped == resumed and len(stopped) == len(result["stopped"]) == len(result["resumed"]),
            "clients not successfully resumed or duplicated")
    require(all(p["status"] == 0 for p in result["resumed"]), "failed resume operation")
    names = {name for _, name in stopped}
    require({"SpringBoard", "backboardd"} <= names <=
            {"SpringBoard", "backboardd", "MercuryPosterExtension"}, "unexpected paused clients")
    identities = {}
    require(set(result["executables"]) == set(build["files"]), "artifact sets differ")
    for name, record in result["executables"].items():
        path = artifacts / name
        require(record["matched"] is True and path.stat().st_size == record["readback_bytes"],
                "incomplete device readback: " + name)
        require(digest(path) == record["sha256"] == build["files"][name]["sha256"] ==
                trust["files"][name]["sha256"], "artifact hash mismatch: " + name)
        require(build["files"][name]["cdhash"] == trust["files"][name]["cdhash"],
                "signature manifest mismatch: " + name)
        identities[name] = dict(bytes=record["readback_bytes"], **build["files"][name])
    fixture_hash = digest(artifacts / "duo-air-probe.metallib")
    fixture = json.loads((artifacts / "fixture-manifest.json").read_text())
    require(fixture_hash == build["fixture_sha256"] == fixture["files"]["duo-air-probe.metallib"],
            "fixture hash mismatch")
    checkpoint = dict(
        schema=1, scope="owned synthetic AIR2.9/Metal4.1 offscreen FD660 shader gate",
        time_utc=datetime.datetime.fromtimestamp(result["time_ns"] / 1e9,
                 datetime.timezone.utc).isoformat(),
        evidence_sha256={p.name: digest(p) for p in (result_path, log_path, kernel_path)},
        artifact_manifest_sha256={n: digest(artifacts / n) for n in
                                 ("build.json", "trust.json", "fixture-manifest.json")},
        image=result["image"], kernel_span_proof=result["kernel_proof"],
        artifacts=identities, fixture_sha256=fixture_hash, target=build["target"],
        sdk=build["sdk_version"], compiler_inputs=build["compiler_inputs"],
        bridge_sha256=build["bridge_sha256"], source_sha256=build["source_sha256"],
        events=events, gpu_draws=4, compared_components=16384,
        float_components_exact=12288, srgb_components_within_one_code=4096,
        client_policy_restored=True, resumed_clients=result["resumed"],
        limitations=["AIR4 diagnostic kernel with legacy global cache behavior",
                     "kernel identity checks only the recorded 128-byte span",
                     "no GPU fault coverage; unsupported status/fault queries in raw log",
                     "single process-global native bridge; unknown DRM fd identity fallback",
                     "CPU elapsed timings; not GPU timestamps, UI throughput or 60/90 Hz",
                     "owned synthetic shaders; not actual compositor pipeline execution",
                     "no system Metal frontend or IOSurface/presentation integration proven"])
    if len(all_events) != len(events):
        checkpoint["other_retained_json_events"] = len(all_events) - len(events)
    if kernel_image is not None:
        checkpoint["kernel_candidate"] = kernel_span(kernel_image, result["kernel_proof"])
        checkpoint["limitations"][0] = (
            "different diagnostic source kernel; identical shader binaries; uncontrolled OS load")
    return checkpoint


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--kernel-log", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--kernel-image", type=Path,
                        help="optional exact candidate; verifies recorded runtime span against file bytes")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = review(args.result, args.log, args.kernel_log, args.artifacts, args.kernel_image)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print("PASS: raw events, four draws, explicit refusal, complete artifact readbacks and client restore")
