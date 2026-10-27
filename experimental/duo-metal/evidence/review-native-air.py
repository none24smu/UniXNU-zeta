#!/usr/bin/env python3
"""Review retained host/device records; never connects to a device."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def review(result_path, log_path, kernel_path, artifacts):
    result = json.loads(result_path.read_text())
    build = json.loads((artifacts / "build.json").read_text())
    trust = json.loads((artifacts / "trust.json").read_text())
    events = [json.loads(line) for line in log_path.read_text().splitlines()
              if line.startswith('{')]
    require(events == result["events"], "raw log and result events differ")
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
    require(stopped == resumed and len(stopped) == 2, "clients not successfully resumed")
    require({name for _, name in stopped} == {"SpringBoard", "backboardd"},
            "unexpected paused clients")
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
    return dict(
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--kernel-log", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = review(args.result, args.log, args.kernel_log, args.artifacts)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print("PASS: raw events, four draws, explicit refusal, complete artifact readbacks and client restore")
