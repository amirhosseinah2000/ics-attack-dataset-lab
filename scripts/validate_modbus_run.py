#!/usr/bin/env python3
"""
Validate one generated Modbus/TCP attack-run dataset directory.

Designed for the ICS Attack Dataset Lab.
Standard-library only: no pandas/PyYAML dependency is required.

Checks:
- required artifacts exist and are non-empty
- raw/labeled row counts match
- label_summary counts match the labeled CSV
- packet labels exactly implement:
      attack iff timestamp is inside attack window
      AND src/dst IP matches attacker IP
- phase, direction, attacker-traffic flag, run/scenario metadata consistency
- attack-family/type consistency
- reconnaissance-specific Modbus checks for MODBUS-RECON scenarios
- request/response transaction pairing when tcp.stream + mbtcp.trans_id exist
- attack_stats request count consistency
- process_state.csv is present and contains samples

Writes validation_report.json into the run directory.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
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


def norm_flag(value: str) -> int | None:
    value = (value or "").strip().lower()
    if value in {"1", "true", "yes"}:
        return 1
    if value in {"0", "false", "no"}:
        return 0
    return None


def norm_func_codes(value: str) -> list[int]:
    """Parse tshark occurrence=a values such as '3', '0x03', or '3,3'."""
    out: list[int] = []
    if value is None:
        return out
    text = value.strip()
    if not text:
        return out

    # TShark can aggregate repeated values with commas.
    for token in text.replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if token.lower().startswith("0x"):
                out.append(int(token, 16))
            else:
                out.append(int(float(token)))
        except ValueError:
            pass
    return out


def safe_float(value: str) -> float | None:
    try:
        x = float((value or "").strip())
        if math.isfinite(x):
            return x
    except (TypeError, ValueError):
        pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, help="Path to one generated run directory")
    ap.add_argument(
        "--report",
        default=None,
        help="Optional report path. Default: <run-dir>/validation_report.json",
    )
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    report_path = Path(args.report).resolve() if args.report else run_dir / "validation_report.json"

    required_files = {
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

    # ------------------------------------------------------------------
    # 1) Artifact presence
    # ------------------------------------------------------------------
    missing = []
    empty = []
    for name, path in required_files.items():
        if not path.exists():
            missing.append(name)
        elif path.stat().st_size == 0:
            empty.append(name)

    if missing:
        fail("required_artifacts_present", {"missing": missing})
    else:
        ok("required_artifacts_present")

    if empty:
        fail("required_artifacts_nonempty", {"empty": empty})
    else:
        ok("required_artifacts_nonempty")

    essential = ["raw_csv", "labeled_csv", "ground_truth", "label_summary"]
    if any(not required_files[k].exists() for k in essential):
        report = {
            "status": "FAIL",
            "run_dir": str(run_dir),
            "failures": failures,
            "warnings": warnings,
            "checks": checks,
        }
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 1

    # ------------------------------------------------------------------
    # 2) Load ground truth / summary / CSVs
    # ------------------------------------------------------------------
    gt_events = load_jsonl(required_files["ground_truth"])
    summary = load_json(required_files["label_summary"])

    attack_starts = [e for e in gt_events if e.get("event") == "attack_start"]
    attack_ends = [e for e in gt_events if e.get("event") == "attack_end"]

    if len(attack_starts) != 1 or len(attack_ends) != 1:
        fail(
            "ground_truth_single_attack_window",
            {"attack_start_events": len(attack_starts), "attack_end_events": len(attack_ends)},
        )
        # Cannot continue safely if attack window is ambiguous.
        report = {
            "status": "FAIL",
            "run_dir": str(run_dir),
            "failures": failures,
            "warnings": warnings,
            "checks": checks,
        }
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 1

    gt_start = attack_starts[0]
    gt_end = attack_ends[0]

    attacker_ip = str(gt_start.get("attacker_ip", "")).strip()
    scenario_id = str(gt_start.get("scenario_id", "")).strip()
    run_id = str(gt_start.get("run_id", "")).strip()
    attack_family = str(gt_start.get("attack_family", "")).strip()
    attack_type = str(gt_start.get("attack_type", "")).strip()
    target_asset = str(gt_start.get("target_asset", "")).strip()
    attack_start = parse_utc(str(gt_start["timestamp_utc"]))
    attack_end = parse_utc(str(gt_end["timestamp_utc"]))

    if attack_end < attack_start:
        fail("ground_truth_window_order", {"start": attack_start, "end": attack_end})
    else:
        ok(
            "ground_truth_window_order",
            {"duration_seconds": round(attack_end - attack_start, 6)},
        )

    # Summary must describe the same run and attack window.
    summary_identity_errors = {}
    for key, expected in {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "attacker_ip": attacker_ip,
    }.items():
        if str(summary.get(key, "")) != expected:
            summary_identity_errors[key] = {
                "summary": summary.get(key),
                "ground_truth": expected,
            }

    for key, expected in {
        "attack_start_epoch": attack_start,
        "attack_end_epoch": attack_end,
    }.items():
        got = summary.get(key)
        try:
            same = abs(float(got) - expected) < 1e-6
        except (TypeError, ValueError):
            same = False
        if not same:
            summary_identity_errors[key] = {"summary": got, "ground_truth": expected}

    if summary_identity_errors:
        fail("summary_matches_ground_truth_identity", summary_identity_errors)
    else:
        ok("summary_matches_ground_truth_identity")

    raw_fields, raw_rows = load_csv(required_files["raw_csv"])
    labeled_fields, rows = load_csv(required_files["labeled_csv"])

    if len(raw_rows) != len(rows):
        fail(
            "raw_and_labeled_row_counts_match",
            {"raw_rows": len(raw_rows), "labeled_rows": len(rows)},
        )
    else:
        ok("raw_and_labeled_row_counts_match", {"rows": len(rows)})

    missing_cols = sorted(REQUIRED_LABEL_COLUMNS - set(labeled_fields))
    if missing_cols:
        fail("required_label_columns", {"missing": missing_cols})
    else:
        ok("required_label_columns")

    # ------------------------------------------------------------------
    # 3) Exact packet-level label semantics
    # ------------------------------------------------------------------
    label_counts = Counter()
    direction_counts = Counter()
    phase_counts = Counter()
    malformed_timestamps = 0
    semantic_errors: list[dict[str, Any]] = []
    metadata_errors: list[dict[str, Any]] = []

    attack_rows: list[dict[str, str]] = []
    target_peers = Counter()
    attack_func_codes = Counter()
    attack_unit_ids = Counter()

    for idx, row in enumerate(rows, start=2):  # CSV header = line 1
        ts = safe_float(row.get("frame.time_epoch", ""))
        if ts is None:
            malformed_timestamps += 1
            if len(semantic_errors) < 20:
                semantic_errors.append({"csv_line": idx, "error": "invalid frame.time_epoch"})
            continue

        src = (row.get("ip.src") or "").strip()
        dst = (row.get("ip.dst") or "").strip()
        binary = (row.get("label_binary") or "").strip()
        direction = (row.get("label_direction") or "").strip()
        phase = (row.get("label_phase") or "").strip()

        label_counts[binary] += 1
        direction_counts[direction] += 1
        phase_counts[phase] += 1

        in_window = attack_start <= ts <= attack_end
        involves_attacker = src == attacker_ip or dst == attacker_ip
        expected_attack = in_window and involves_attacker

        if ts < attack_start:
            expected_phase = "warmup"
        elif ts <= attack_end:
            expected_phase = "attack"
        else:
            expected_phase = "recovery"

        if expected_attack:
            expected_binary = "attack"
            if src == attacker_ip:
                expected_direction = "attacker_to_target"
                target_peers[dst] += 1
            else:
                expected_direction = "target_to_attacker"
                target_peers[src] += 1
        else:
            expected_binary = "normal"
            expected_direction = (
                "background_during_attack" if in_window and not involves_attacker else "background"
            )

        row_errors = {}
        if binary != expected_binary:
            row_errors["label_binary"] = {"got": binary, "expected": expected_binary}
        if direction != expected_direction:
            row_errors["label_direction"] = {"got": direction, "expected": expected_direction}
        if phase != expected_phase:
            row_errors["label_phase"] = {"got": phase, "expected": expected_phase}

        got_attacker_flag = norm_flag(row.get("label_is_attacker_traffic", ""))
        expected_flag = 1 if involves_attacker else 0
        if got_attacker_flag != expected_flag:
            row_errors["label_is_attacker_traffic"] = {
                "got": row.get("label_is_attacker_traffic"),
                "expected": expected_flag,
            }

        if row_errors and len(semantic_errors) < 20:
            semantic_errors.append(
                {
                    "csv_line": idx,
                    "frame.time_epoch": ts,
                    "ip.src": src,
                    "ip.dst": dst,
                    "errors": row_errors,
                }
            )

        # Metadata copied into every row.
        expected_meta = {
            "label_attacker_ip": attacker_ip,
            "label_scenario_id": scenario_id,
            "label_run_id": run_id,
            "label_target_asset": target_asset,
        }
        meta_err = {}
        for key, expected in expected_meta.items():
            if (row.get(key) or "").strip() != expected:
                meta_err[key] = {"got": row.get(key), "expected": expected}

        if expected_attack:
            if (row.get("label_attack_family") or "").strip() != attack_family:
                meta_err["label_attack_family"] = {
                    "got": row.get("label_attack_family"),
                    "expected": attack_family,
                }
            if (row.get("label_attack_type") or "").strip() != attack_type:
                meta_err["label_attack_type"] = {
                    "got": row.get("label_attack_type"),
                    "expected": attack_type,
                }
            attack_rows.append(row)

            for fc in norm_func_codes(row.get("modbus.func_code", "")):
                attack_func_codes[fc] += 1

            unit = (row.get("mbtcp.unit_id") or "").strip()
            if unit:
                attack_unit_ids[unit] += 1
        else:
            if (row.get("label_attack_family") or "").strip():
                meta_err["label_attack_family"] = {
                    "got": row.get("label_attack_family"),
                    "expected": "",
                }
            if (row.get("label_attack_type") or "").strip():
                meta_err["label_attack_type"] = {
                    "got": row.get("label_attack_type"),
                    "expected": "",
                }

        if meta_err and len(metadata_errors) < 20:
            metadata_errors.append({"csv_line": idx, "errors": meta_err})

    if malformed_timestamps:
        fail("all_packet_timestamps_parse", {"invalid_rows": malformed_timestamps})
    else:
        ok("all_packet_timestamps_parse")

    if semantic_errors:
        fail(
            "packet_label_semantics",
            {
                "sample_errors": semantic_errors,
                "note": "At most 20 sample errors are shown.",
            },
        )
    else:
        ok("packet_label_semantics")

    if metadata_errors:
        fail(
            "packet_label_metadata",
            {
                "sample_errors": metadata_errors,
                "note": "At most 20 sample errors are shown.",
            },
        )
    else:
        ok("packet_label_metadata")

    if set(label_counts) - {"normal", "attack"}:
        fail("binary_label_domain", {"counts": dict(label_counts)})
    else:
        ok("binary_label_domain", {"counts": dict(label_counts)})

    # ------------------------------------------------------------------
    # 4) label_summary must be exactly reproducible from the CSV
    # ------------------------------------------------------------------
    expected_summary_counts = {
        "normal_rows": label_counts.get("normal", 0),
        "attack_rows": label_counts.get("attack", 0),
        "attacker_to_target_rows": direction_counts.get("attacker_to_target", 0),
        "target_to_attacker_rows": direction_counts.get("target_to_attacker", 0),
        "background_rows_during_attack_window": direction_counts.get(
            "background_during_attack", 0
        ),
    }

    summary_count_errors = {}
    for key, actual in expected_summary_counts.items():
        try:
            saved = int(summary.get(key))
        except (TypeError, ValueError):
            saved = None
        if saved != actual:
            summary_count_errors[key] = {"summary": saved, "csv": actual}

    if summary_count_errors:
        fail("summary_counts_reproducible", summary_count_errors)
    else:
        ok("summary_counts_reproducible", expected_summary_counts)

    if label_counts.get("normal", 0) + label_counts.get("attack", 0) != len(rows):
        fail(
            "all_rows_have_binary_label",
            {
                "rows": len(rows),
                "normal": label_counts.get("normal", 0),
                "attack": label_counts.get("attack", 0),
            },
        )
    else:
        ok("all_rows_have_binary_label")

    # ------------------------------------------------------------------
    # 5) Reconnaissance scenario protocol checks
    # ------------------------------------------------------------------
    recon_checks = scenario_id.startswith("MODBUS-RECON") or attack_type == "unauthorized_read"

    if recon_checks:
        req_count = direction_counts.get("attacker_to_target", 0)
        resp_count = direction_counts.get("target_to_attacker", 0)

        if req_count != resp_count:
            fail(
                "recon_request_response_direction_balance",
                {"requests": req_count, "responses": resp_count},
            )
        else:
            ok(
                "recon_request_response_direction_balance",
                {"requests": req_count, "responses": resp_count},
            )

        # Only FC1 (Read Coils) and FC3 (Read Holding Registers) are expected
        # from this specific recon generator.
        observed_fcs = sorted(attack_func_codes)
        unexpected_fcs = sorted(set(observed_fcs) - {1, 3})
        write_fcs = sorted(set(observed_fcs) & {5, 6, 15, 16})

        if unexpected_fcs:
            fail(
                "recon_function_codes",
                {
                    "observed": observed_fcs,
                    "unexpected": unexpected_fcs,
                    "counts": dict(attack_func_codes),
                },
            )
        elif not observed_fcs:
            warn(
                "recon_function_codes",
                "modbus.func_code is empty on attack rows; protocol-level FC validation skipped.",
            )
        else:
            ok("recon_function_codes", {"counts": dict(attack_func_codes)})

        if write_fcs:
            fail("recon_contains_no_write_function_codes", {"write_fcs": write_fcs})
        else:
            ok("recon_contains_no_write_function_codes")

        if len(target_peers) != 1:
            fail("recon_single_target_peer", {"peer_counts": dict(target_peers)})
        else:
            ok("recon_single_target_peer", {"peer_counts": dict(target_peers)})

        # Unit ID should be 1 for this scenario when the field is available.
        if attack_unit_ids:
            bad_units = {
                unit: count
                for unit, count in attack_unit_ids.items()
                if unit not in {"1", "1.0", "0x01"}
            }
            if bad_units:
                fail(
                    "recon_unit_id",
                    {"counts": dict(attack_unit_ids), "unexpected": bad_units},
                )
            else:
                ok("recon_unit_id", {"counts": dict(attack_unit_ids)})
        else:
            warn("recon_unit_id", "mbtcp.unit_id unavailable/empty on attack rows.")

        # Transaction pairing.
        has_stream = "tcp.stream" in labeled_fields
        has_tid = "mbtcp.trans_id" in labeled_fields

        if has_tid:
            tx = defaultdict(lambda: {"req": [], "resp": []})
            for row in attack_rows:
                tid = (row.get("mbtcp.trans_id") or "").strip()
                if not tid:
                    continue
                stream = (row.get("tcp.stream") or "").strip() if has_stream else ""
                key = (stream, tid)

                src = (row.get("ip.src") or "").strip()
                dst = (row.get("ip.dst") or "").strip()
                ts = safe_float(row.get("frame.time_epoch", ""))

                record = {
                    "ts": ts,
                    "fc": norm_func_codes(row.get("modbus.func_code", "")),
                    "src": src,
                    "dst": dst,
                }
                if src == attacker_ip:
                    tx[key]["req"].append(record)
                elif dst == attacker_ip:
                    tx[key]["resp"].append(record)

            pair_errors = []
            paired = 0
            for key, pair in tx.items():
                reqs = pair["req"]
                resps = pair["resp"]
                if len(reqs) == 1 and len(resps) == 1:
                    paired += 1
                    req = reqs[0]
                    resp = resps[0]

                    if req["ts"] is not None and resp["ts"] is not None and req["ts"] > resp["ts"]:
                        pair_errors.append(
                            {"transaction": key, "error": "response timestamp precedes request"}
                        )

                    if req["fc"] and resp["fc"] and req["fc"][0] != resp["fc"][0]:
                        # Exception responses can use FC | 0x80; those are not expected here,
                        # but make the diagnostic explicit.
                        if resp["fc"][0] != (req["fc"][0] | 0x80):
                            pair_errors.append(
                                {
                                    "transaction": key,
                                    "error": "request/response function code mismatch",
                                    "request_fc": req["fc"],
                                    "response_fc": resp["fc"],
                                }
                            )
                else:
                    pair_errors.append(
                        {
                            "transaction": key,
                            "request_rows": len(reqs),
                            "response_rows": len(resps),
                        }
                    )

                if len(pair_errors) >= 20:
                    break

            if pair_errors:
                fail(
                    "recon_transaction_pairing",
                    {
                        "transactions_seen": len(tx),
                        "paired_transactions": paired,
                        "sample_errors": pair_errors,
                    },
                )
            else:
                ok(
                    "recon_transaction_pairing",
                    {
                        "transactions_seen": len(tx),
                        "paired_transactions": paired,
                    },
                )
        else:
            warn(
                "recon_transaction_pairing",
                "mbtcp.trans_id column unavailable; transaction-level pairing skipped.",
            )

    # ------------------------------------------------------------------
    # 6) attack_stats consistency
    # ------------------------------------------------------------------
    if required_files["attack_stats"].exists() and required_files["attack_stats"].stat().st_size:
        try:
            stats = load_json(required_files["attack_stats"])
            attempted = int(stats.get("holding_reads_attempted", 0)) + int(
                stats.get("coil_reads_attempted", 0)
            )
            request_rows = direction_counts.get("attacker_to_target", 0)

            if attempted != request_rows:
                fail(
                    "attack_stats_request_count_matches_packets",
                    {"attempted_requests": attempted, "request_packet_rows": request_rows},
                )
            else:
                ok(
                    "attack_stats_request_count_matches_packets",
                    {"attempted_requests": attempted},
                )

            errors = int(stats.get("errors", 0))
            if errors:
                warn("attack_stats_errors", {"errors": errors})
            else:
                ok("attack_stats_errors", {"errors": 0})
        except Exception as exc:
            fail("attack_stats_parse", str(exc))

    # ------------------------------------------------------------------
    # 7) process-state basic sanity
    # ------------------------------------------------------------------
    if required_files["process_state"].exists() and required_files["process_state"].stat().st_size:
        try:
            p_fields, p_rows = load_csv(required_files["process_state"])
            if not p_rows:
                fail("process_state_has_samples", {"rows": 0})
            else:
                ok(
                    "process_state_has_samples",
                    {"rows": len(p_rows), "columns": p_fields},
                )
        except Exception as exc:
            fail("process_state_parse", str(exc))

    # ------------------------------------------------------------------
    # Final report
    # ------------------------------------------------------------------
    status = "FAIL" if failures else ("WARN" if warnings else "PASS")

    report = {
        "status": status,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "run_dir": str(run_dir),
        "attack_window_seconds": round(attack_end - attack_start, 6),
        "packet_rows": len(rows),
        "label_counts": dict(label_counts),
        "direction_counts": dict(direction_counts),
        "phase_counts": dict(phase_counts),
        "target_peer_counts": dict(target_peers),
        "attack_function_code_counts": {str(k): v for k, v in sorted(attack_func_codes.items())},
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
    print(f"Rows         : {len(rows)}")
    print(f"Normal       : {label_counts.get('normal', 0)}")
    print(f"Attack       : {label_counts.get('attack', 0)}")
    print(f"Req/Resp     : {direction_counts.get('attacker_to_target', 0)} / "
          f"{direction_counts.get('target_to_attacker', 0)}")
    print(f"Background@A : {direction_counts.get('background_during_attack', 0)}")
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
