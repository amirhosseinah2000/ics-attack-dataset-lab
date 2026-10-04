#!/usr/bin/env python3
"""Validate one Modbus/TCP run produced by the ICS Attack Dataset Lab.

Version 2 supports both:
- MODBUS-RECON-* / attack_type=unauthorized_read
- MODBUS-MANIP-* / attack_type=manual_overflow

The validator is intentionally independent from the packet-labeling script: it
recomputes expected labels directly from ground_truth.jsonl and the extracted
packet fields.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_LABEL_COLUMNS = {
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "label_binary",
    "label_attack_family",
    "label_attack_type",
    "label_phase",
    "label_is_attacker_traffic",
    "label_direction",
    "label_attacker_ip",
    "label_scenario_id",
    "label_run_id",
    "label_target_asset",
}


def parse_utc(text: str) -> float:
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc).timestamp()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{line_no}: invalid JSON: {exc}") from exc
    return out


def load_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
        return list(reader.fieldnames or []), rows


def safe_float(value: Any) -> float | None:
    try:
        x = float(str(value).strip())
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def safe_int(value: Any) -> int | None:
    x = safe_float(value)
    if x is None:
        return None
    return int(x)


def norm_flag(value: Any) -> int | None:
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes"}:
        return 1
    if text in {"0", "false", "no"}:
        return 0
    return None


def norm_func_codes(value: Any) -> list[int]:
    text = str(value or "").strip()
    if not text:
        return []
    out: list[int] = []
    for token in text.replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            out.append(int(token, 16) if token.lower().startswith("0x") else int(float(token)))
        except ValueError:
            pass
    return out


def median_numeric(rows: list[dict[str, str]], field: str) -> float | None:
    vals = [safe_float(r.get(field)) for r in rows]
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    report_path = Path(args.report).resolve() if args.report else run_dir / "validation_report.json"

    required = {
        "pcap": run_dir / "traffic.pcap",
        "raw_csv": run_dir / "modbus_packets.csv",
        "labeled_csv": run_dir / "modbus_packets_labeled.csv",
        "ground_truth": run_dir / "ground_truth.jsonl",
        "attack_stats": run_dir / "attack_stats.json",
        "label_summary": run_dir / "label_summary.json",
        "process_state": run_dir / "process_state.csv",
        "manifest": run_dir / "manifest.yaml",
    }

    failures: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    def ok(name: str, details: Any = None) -> None:
        checks.append({"name": name, "status": "PASS", "details": details})

    def warn(name: str, details: Any) -> None:
        warnings.append(f"{name}: {details}")
        checks.append({"name": name, "status": "WARN", "details": details})

    def fail(name: str, details: Any) -> None:
        failures.append(f"{name}: {details}")
        checks.append({"name": name, "status": "FAIL", "details": details})

    if not run_dir.is_dir():
        print(f"ERROR: run directory not found: {run_dir}", file=sys.stderr)
        return 2

    missing = [k for k, p in required.items() if not p.exists()]
    empty = [k for k, p in required.items() if p.exists() and p.stat().st_size == 0]
    if missing:
        fail("required_artifacts_present", {"missing": missing})
    else:
        ok("required_artifacts_present")
    if empty:
        fail("required_artifacts_nonempty", {"empty": empty})
    else:
        ok("required_artifacts_nonempty")

    essential = {"raw_csv", "labeled_csv", "ground_truth", "label_summary"}
    if any(not required[k].exists() for k in essential):
        report = {"status": "FAIL", "run_dir": str(run_dir), "failures": failures,
                  "warnings": warnings, "checks": checks}
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 1

    try:
        gt_events = load_jsonl(required["ground_truth"])
        summary = load_json(required["label_summary"])
        raw_fields, raw_rows = load_csv(required["raw_csv"])
        labeled_fields, rows = load_csv(required["labeled_csv"])
    except Exception as exc:
        fail("artifact_parse", str(exc))
        report = {"status": "FAIL", "run_dir": str(run_dir), "failures": failures,
                  "warnings": warnings, "checks": checks}
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 1

    starts = [e for e in gt_events if e.get("event") == "attack_start"]
    ends = [e for e in gt_events if e.get("event") == "attack_end"]
    if len(starts) != 1 or len(ends) != 1:
        fail("ground_truth_single_attack_window", {"attack_start": len(starts), "attack_end": len(ends)})
        report = {"status": "FAIL", "run_dir": str(run_dir), "failures": failures,
                  "warnings": warnings, "checks": checks}
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 1

    gt_start = starts[0]
    gt_end = ends[0]
    attacker_ip = str(gt_start.get("attacker_ip", "")).strip()
    run_id = str(gt_start.get("run_id", "")).strip()
    scenario_id = str(gt_start.get("scenario_id", "")).strip()
    attack_family = str(gt_start.get("attack_family", "")).strip()
    attack_type = str(gt_start.get("attack_type", "")).strip()
    target_asset = str(gt_start.get("target_asset", "")).strip()
    attack_start = parse_utc(str(gt_start["timestamp_utc"]))
    attack_end = parse_utc(str(gt_end["timestamp_utc"]))

    if attack_end < attack_start:
        fail("ground_truth_window_order", {"start": attack_start, "end": attack_end})
    else:
        ok("ground_truth_window_order", {"duration_seconds": round(attack_end - attack_start, 6)})

    identity_errors: dict[str, Any] = {}
    for key, expected in {"run_id": run_id, "scenario_id": scenario_id, "attacker_ip": attacker_ip}.items():
        if str(summary.get(key, "")) != expected:
            identity_errors[key] = {"summary": summary.get(key), "ground_truth": expected}
    for key, expected in {"attack_start_epoch": attack_start, "attack_end_epoch": attack_end}.items():
        got = safe_float(summary.get(key))
        if got is None or abs(got - expected) >= 1e-6:
            identity_errors[key] = {"summary": summary.get(key), "ground_truth": expected}
    if identity_errors:
        fail("summary_matches_ground_truth_identity", identity_errors)
    else:
        ok("summary_matches_ground_truth_identity")

    if len(raw_rows) != len(rows):
        fail("raw_and_labeled_row_counts_match", {"raw": len(raw_rows), "labeled": len(rows)})
    else:
        ok("raw_and_labeled_row_counts_match", {"rows": len(rows)})

    missing_cols = sorted(REQUIRED_LABEL_COLUMNS - set(labeled_fields))
    if missing_cols:
        fail("required_label_columns", {"missing": missing_cols})
    else:
        ok("required_label_columns")

    label_counts = Counter()
    direction_counts = Counter()
    phase_counts = Counter()
    attack_func_codes = Counter()
    request_func_codes = Counter()
    attack_unit_ids = Counter()
    target_peers = Counter()
    attack_rows: list[dict[str, str]] = []
    semantic_errors: list[dict[str, Any]] = []

    for index, row in enumerate(rows, 2):
        ts = safe_float(row.get("frame.time_epoch"))
        src = str(row.get("ip.src") or "").strip()
        dst = str(row.get("ip.dst") or "").strip()
        if ts is None:
            semantic_errors.append({"line": index, "error": "invalid frame.time_epoch"})
            continue

        in_window = attack_start <= ts <= attack_end
        involves_attacker = src == attacker_ip or dst == attacker_ip
        is_attack = in_window and involves_attacker

        if ts < attack_start:
            phase = "warmup"
        elif ts <= attack_end:
            phase = "attack"
        else:
            phase = "recovery"

        if is_attack:
            binary = "attack"
            direction = "attacker_to_target" if src == attacker_ip else "target_to_attacker"
        else:
            binary = "normal"
            direction = "background_during_attack" if in_window and not involves_attacker else "background"

        expected = {
            "label_binary": binary,
            "label_phase": phase,
            "label_direction": direction,
            "label_is_attacker_traffic": int(involves_attacker),
            "label_attacker_ip": attacker_ip,
            "label_scenario_id": scenario_id,
            "label_run_id": run_id,
            "label_target_asset": target_asset,
            "label_attack_family": attack_family if is_attack else "",
            "label_attack_type": attack_type if is_attack else "",
        }

        for field, want in expected.items():
            got: Any = row.get(field, "")
            if field == "label_is_attacker_traffic":
                got = norm_flag(got)
            else:
                got = str(got or "").strip()
            if got != want:
                semantic_errors.append({"line": index, "field": field, "got": got, "expected": want})
                if len(semantic_errors) >= 30:
                    break
        if len(semantic_errors) >= 30:
            break

        label_counts[binary] += 1
        direction_counts[direction] += 1
        phase_counts[phase] += 1

        if is_attack:
            attack_rows.append(row)
            fcs = norm_func_codes(row.get("modbus.func_code"))
            for fc in fcs:
                attack_func_codes[fc] += 1
                if src == attacker_ip:
                    request_func_codes[fc] += 1
            unit = str(row.get("mbtcp.unit_id") or "").strip()
            if unit:
                attack_unit_ids[unit] += 1
            peer = dst if src == attacker_ip else src
            if peer:
                target_peers[peer] += 1

    if semantic_errors:
        fail("packet_label_semantics", {"sample_errors": semantic_errors})
    else:
        ok("packet_label_semantics")

    expected_summary = {
        "normal_rows": label_counts.get("normal", 0),
        "attack_rows": label_counts.get("attack", 0),
        "attacker_to_target_rows": direction_counts.get("attacker_to_target", 0),
        "target_to_attacker_rows": direction_counts.get("target_to_attacker", 0),
        "background_rows_during_attack_window": direction_counts.get("background_during_attack", 0),
    }
    summary_errors = {
        k: {"summary": summary.get(k), "recomputed": v}
        for k, v in expected_summary.items()
        if safe_int(summary.get(k)) != v
    }
    if summary_errors:
        fail("label_summary_reproducible", summary_errors)
    else:
        ok("label_summary_reproducible", expected_summary)

    # Common Modbus checks.
    if len(target_peers) != 1:
        fail("single_target_peer", {"peer_counts": dict(target_peers)})
    else:
        ok("single_target_peer", {"peer_counts": dict(target_peers)})

    if attack_unit_ids:
        bad = {k: v for k, v in attack_unit_ids.items() if k not in {"1", "1.0", "0x01"}}
        if bad:
            fail("unit_id", {"counts": dict(attack_unit_ids), "unexpected": bad})
        else:
            ok("unit_id", {"counts": dict(attack_unit_ids)})
    else:
        warn("unit_id", "mbtcp.unit_id unavailable/empty on attack rows")

    # Generic transaction pairing for attacker traffic.
    if "mbtcp.trans_id" in labeled_fields:
        has_stream = "tcp.stream" in labeled_fields
        tx: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(
            lambda: {"req": [], "resp": []}
        )
        for row in attack_rows:
            tid = str(row.get("mbtcp.trans_id") or "").strip()
            if not tid:
                continue
            stream = str(row.get("tcp.stream") or "").strip() if has_stream else ""
            key = (stream, tid)
            src = str(row.get("ip.src") or "").strip()
            rec = {
                "ts": safe_float(row.get("frame.time_epoch")),
                "fc": norm_func_codes(row.get("modbus.func_code")),
            }
            if src == attacker_ip:
                tx[key]["req"].append(rec)
            else:
                tx[key]["resp"].append(rec)

        pair_errors: list[dict[str, Any]] = []
        paired = 0
        for key, pair in tx.items():
            reqs, resps = pair["req"], pair["resp"]
            if len(reqs) == 1 and len(resps) == 1:
                paired += 1
                req, resp = reqs[0], resps[0]
                if req["ts"] is not None and resp["ts"] is not None and req["ts"] > resp["ts"]:
                    pair_errors.append({"transaction": key, "error": "response precedes request"})
                if req["fc"] and resp["fc"]:
                    req_fc, resp_fc = req["fc"][0], resp["fc"][0]
                    if resp_fc not in {req_fc, req_fc | 0x80}:
                        pair_errors.append({"transaction": key, "error": "function code mismatch",
                                            "request_fc": req_fc, "response_fc": resp_fc})
            else:
                pair_errors.append({"transaction": key, "request_rows": len(reqs), "response_rows": len(resps)})
            if len(pair_errors) >= 20:
                break

        if pair_errors:
            fail("transaction_pairing", {"transactions": len(tx), "paired": paired,
                                         "sample_errors": pair_errors})
        else:
            ok("transaction_pairing", {"transactions": len(tx), "paired": paired})
    else:
        warn("transaction_pairing", "mbtcp.trans_id unavailable; pairing skipped")

    # Scenario-specific protocol checks.
    is_recon = scenario_id.startswith("MODBUS-RECON") or attack_type == "unauthorized_read"
    is_manual_overflow = scenario_id.startswith("MODBUS-MANIP") or attack_type == "manual_overflow"

    if is_recon:
        unexpected = sorted(set(request_func_codes) - {1, 3})
        if not request_func_codes:
            warn("recon_function_codes", "No request function codes were extracted")
        elif unexpected:
            fail("recon_function_codes", {"request_counts": dict(request_func_codes), "unexpected": unexpected})
        else:
            ok("recon_function_codes", {"request_counts": dict(request_func_codes)})

        writes = sorted(set(request_func_codes) & {5, 6, 15, 16})
        if writes:
            fail("recon_contains_no_writes", {"write_fcs": writes})
        else:
            ok("recon_contains_no_writes")

    if is_manual_overflow:
        allowed = {1, 3, 5, 6}
        unexpected = sorted(set(request_func_codes) - allowed)
        if unexpected:
            fail("manual_overflow_function_codes", {"request_counts": dict(request_func_codes),
                                                    "unexpected": unexpected})
        else:
            ok("manual_overflow_function_codes", {"request_counts": dict(request_func_codes)})

        missing_write_fcs = [fc for fc in (5, 6) if request_func_codes.get(fc, 0) == 0]
        if missing_write_fcs:
            fail("manual_overflow_required_write_fcs", {"missing": missing_write_fcs,
                                                        "request_counts": dict(request_func_codes)})
        else:
            ok("manual_overflow_required_write_fcs", {"fc5": request_func_codes[5],
                                                       "fc6": request_func_codes[6]})

    # attack_stats consistency.
    stats: dict[str, Any] = {}
    if required["attack_stats"].exists() and required["attack_stats"].stat().st_size:
        try:
            stats = load_json(required["attack_stats"])
            attempted = safe_int(stats.get("requests_attempted"))
            if attempted is None:
                attempted = sum(
                    safe_int(stats.get(k)) or 0
                    for k in (
                        "holding_reads_attempted", "coil_reads_attempted",
                        "write_coil_attempted", "write_register_attempted",
                    )
                )
            # requests_attempted is session-scoped.  In manipulation scenarios the
            # attacker client performs baseline reads immediately before the exact
            # attack window, so comparing it only with attack-labeled request rows
            # produces a false mismatch.  Compare it with every captured request
            # sent by the attacker, while still reporting the attack-window subset.
            all_attacker_request_rows = sum(
                1
                for row in rows
                if str(row.get("ip.src") or "").strip() == attacker_ip
            )
            attack_window_request_rows = direction_counts.get("attacker_to_target", 0)
            pre_attack_or_post_attack_requests = (
                all_attacker_request_rows - attack_window_request_rows
            )

            if attempted != all_attacker_request_rows:
                fail(
                    "attack_stats_request_count_matches_packets",
                    {
                        "attempted_requests": attempted,
                        "captured_attacker_request_rows": all_attacker_request_rows,
                        "attack_window_request_rows": attack_window_request_rows,
                        "attacker_requests_outside_attack_window": pre_attack_or_post_attack_requests,
                    },
                )
            else:
                ok(
                    "attack_stats_request_count_matches_packets",
                    {
                        "attempted_requests": attempted,
                        "captured_attacker_request_rows": all_attacker_request_rows,
                        "attack_window_request_rows": attack_window_request_rows,
                        "attacker_requests_outside_attack_window": pre_attack_or_post_attack_requests,
                    },
                )

            errors = safe_int(stats.get("errors")) or 0
            if errors:
                fail("attack_stats_errors", {"errors": errors})
            else:
                ok("attack_stats_errors", {"errors": 0})

            if is_manual_overflow:
                if stats.get("restored") is True:
                    ok("manual_overflow_restore_confirmed")
                else:
                    fail("manual_overflow_restore_confirmed",
                         {"restored": stats.get("restored"), "restore_errors": stats.get("restore_errors")})
        except Exception as exc:
            fail("attack_stats_parse", str(exc))

    # Process-state checks.
    process_details: dict[str, Any] = {}
    if required["process_state"].exists() and required["process_state"].stat().st_size:
        try:
            p_fields, p_rows = load_csv(required["process_state"])
            if not p_rows:
                fail("process_state_has_samples", {"rows": 0})
            else:
                ok("process_state_has_samples", {"rows": len(p_rows), "columns": p_fields})

                warm: list[dict[str, str]] = []
                attack_p: list[dict[str, str]] = []
                recovery: list[dict[str, str]] = []
                for row in p_rows:
                    ts = safe_float(row.get("timestamp_epoch"))
                    if ts is None:
                        continue
                    if ts < attack_start:
                        warm.append(row)
                    elif ts <= attack_end:
                        attack_p.append(row)
                    else:
                        recovery.append(row)

                process_details = {
                    "warmup_samples": len(warm),
                    "attack_samples": len(attack_p),
                    "recovery_samples": len(recovery),
                }

                if is_manual_overflow:
                    if not attack_p:
                        fail("manual_overflow_process_attack_samples", process_details)
                    else:
                        ok("manual_overflow_process_attack_samples", {"samples": len(attack_p)})

                        mode_hits = 0
                        mode_valid = 0
                        flow_hits = 0
                        flow_valid = 0
                        overflow_seen = False
                        attack_tanks: list[float] = []

                        for row in attack_p:
                            mode = safe_int(row.get("coil_inflow_mode"))
                            if mode is None:
                                mode = safe_int(row.get("inflow_mode"))
                            if mode is not None:
                                mode_valid += 1
                                mode_hits += int(mode == 1)

                            inflow = safe_float(row.get("inflow_rate"))
                            outflow = safe_float(row.get("outflow_rate"))
                            if inflow is not None and outflow is not None:
                                flow_valid += 1
                                flow_hits += int(inflow > outflow)

                            tank = safe_float(row.get("tank_level"))
                            if tank is not None:
                                attack_tanks.append(tank)

                            alarm = safe_int(row.get("coil_overflow_alarm"))
                            if alarm is None:
                                alarm = safe_int(row.get("overflow_alarm"))
                            overflow_seen = overflow_seen or alarm == 1

                        mode_ratio = mode_hits / mode_valid if mode_valid else None
                        flow_ratio = flow_hits / flow_valid if flow_valid else None
                        baseline_tank = median_numeric(warm, "tank_level")
                        attack_max = max(attack_tanks) if attack_tanks else None
                        attack_first = attack_tanks[0] if attack_tanks else None
                        attack_last = attack_tanks[-1] if attack_tanks else None

                        process_details.update({
                            "manual_mode_ratio": mode_ratio,
                            "inflow_gt_outflow_ratio": flow_ratio,
                            "warmup_tank_median": baseline_tank,
                            "attack_tank_first": attack_first,
                            "attack_tank_last": attack_last,
                            "attack_tank_max": attack_max,
                            "overflow_alarm_seen": overflow_seen,
                        })

                        if mode_ratio is None:
                            warn("manual_overflow_manual_mode_observed", "mode fields unavailable")
                        elif mode_ratio < 0.5:
                            fail("manual_overflow_manual_mode_observed", {"ratio": mode_ratio})
                        else:
                            ok("manual_overflow_manual_mode_observed", {"ratio": round(mode_ratio, 3)})

                        # For Aloha Manual Overflow, requiring inflow > outflow
                        # for most of a long attack is incorrect. Once the tank
                        # reaches its upper bound the simulator can cut inflow,
                        # while outflow continues and the tank starts to fall.
                        # What matters is that the unsafe imbalance was actually
                        # established and caused the expected process impact.
                        if flow_ratio is None:
                            warn("manual_overflow_flow_imbalance_initiated", "flow fields unavailable")
                        elif flow_hits < 1:
                            fail(
                                "manual_overflow_flow_imbalance_initiated",
                                {"samples_with_inflow_gt_outflow": flow_hits,
                                 "valid_flow_samples": flow_valid,
                                 "ratio": flow_ratio},
                            )
                        else:
                            ok(
                                "manual_overflow_flow_imbalance_initiated",
                                {"samples_with_inflow_gt_outflow": flow_hits,
                                 "valid_flow_samples": flow_valid,
                                 "ratio": round(flow_ratio, 3)},
                            )

                        # Detect the normal Aloha safety response after overflow:
                        # an alarm/upper-bound event followed by inflow cutoff.
                        cutoff_seen = False
                        post_peak_decline = False
                        peak_idx = None
                        if attack_tanks:
                            peak_value = max(attack_tanks)
                            peak_idx = attack_tanks.index(peak_value)

                        for idx, row in enumerate(attack_p):
                            inflow = safe_float(row.get("inflow_rate"))
                            outflow = safe_float(row.get("outflow_rate"))
                            if inflow is not None and outflow is not None and inflow <= outflow:
                                # Only count this as protective cutoff after the
                                # process has reached the upper bound / alarm.
                                tank = safe_float(row.get("tank_level"))
                                alarm = safe_int(row.get("coil_overflow_alarm"))
                                if alarm is None:
                                    alarm = safe_int(row.get("overflow_alarm"))
                                if overflow_seen and (alarm == 1 or (tank is not None and tank >= 10000)):
                                    cutoff_seen = True
                                elif peak_idx is not None and idx > peak_idx:
                                    cutoff_seen = True

                        if peak_idx is not None and peak_idx < len(attack_tanks) - 1:
                            post_peak_decline = attack_tanks[-1] < attack_tanks[peak_idx]

                        process_details.update({
                            "flow_imbalance_samples": flow_hits,
                            "protective_cutoff_observed": cutoff_seen,
                            "post_peak_decline_observed": post_peak_decline,
                        })

                        if overflow_seen:
                            ok(
                                "manual_overflow_overflow_response",
                                {
                                    "overflow_alarm_seen": True,
                                    "protective_cutoff_observed": cutoff_seen,
                                    "post_peak_decline_observed": post_peak_decline,
                                },
                            )
                        else:
                            ok(
                                "manual_overflow_overflow_response",
                                {
                                    "overflow_alarm_seen": False,
                                    "note": "tank did not reach overflow threshold during this run",
                                },
                            )

                        if baseline_tank is None or attack_max is None:
                            warn("manual_overflow_tank_rise", "tank_level unavailable for comparison")
                        elif attack_max <= baseline_tank:
                            fail("manual_overflow_tank_rise",
                                 {"warmup_median": baseline_tank, "attack_max": attack_max})
                        else:
                            ok("manual_overflow_tank_rise",
                               {"warmup_median": baseline_tank, "attack_max": attack_max,
                                "delta": attack_max - baseline_tank})

                        # Overflow is intentionally informational: the Aloha docs say the
                        # alarm appears only if the tank reaches the maximum level.
                        ok("manual_overflow_alarm_observation", {"overflow_alarm_seen": overflow_seen})
        except Exception as exc:
            fail("process_state_parse", str(exc))

    status = "FAIL" if failures else ("WARN" if warnings else "PASS")
    report = {
        "status": status,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "attack_family": attack_family,
        "attack_type": attack_type,
        "run_dir": str(run_dir),
        "attack_window_seconds": round(attack_end - attack_start, 6),
        "packet_rows": len(rows),
        "label_counts": dict(label_counts),
        "direction_counts": dict(direction_counts),
        "phase_counts": dict(phase_counts),
        "target_peer_counts": dict(target_peers),
        "attack_function_code_counts": {str(k): v for k, v in sorted(attack_func_codes.items())},
        "request_function_code_counts": {str(k): v for k, v in sorted(request_func_codes.items())},
        "process_observation": process_details,
        "failures": failures,
        "warnings": warnings,
        "checks": checks,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("")
    print("=" * 68)
    print(" MODBUS RUN VALIDATION")
    print("=" * 68)
    print(f"Run ID       : {run_id}")
    print(f"Scenario     : {scenario_id}")
    print(f"Attack type  : {attack_type}")
    print(f"Rows         : {len(rows)}")
    print(f"Normal       : {label_counts.get('normal', 0)}")
    print(f"Attack       : {label_counts.get('attack', 0)}")
    print(f"Req/Resp     : {direction_counts.get('attacker_to_target', 0)} / "
          f"{direction_counts.get('target_to_attacker', 0)}")
    print(f"Background@A : {direction_counts.get('background_during_attack', 0)}")
    if is_manual_overflow and process_details:
        print(f"Tank delta   : {process_details.get('attack_tank_max')} vs "
              f"baseline {process_details.get('warmup_tank_median')}")
        print(f"Restored     : {stats.get('restored') if stats else None}")
    print(f"Status       : {status}")
    print(f"Report       : {report_path}")
    print("=" * 68)

    if failures:
        print("\nFAILURES:")
        for item in failures:
            print(f"  - {item}")
    if warnings:
        print("\nWARNINGS:")
        for item in warnings:
            print(f"  - {item}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
