#!/usr/bin/env python3
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_utc(text: str) -> float:
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc).timestamp()


def load_ground_truth(path: Path):
    events = []
    with path.open("r", encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    attack_start = next(e for e in events if e.get("event") == "attack_start")
    attack_end = next(e for e in events if e.get("event") == "attack_end")

    attacker_ip = attack_start["attacker_ip"]
    start_epoch = parse_utc(attack_start["timestamp_utc"])
    end_epoch = parse_utc(attack_end["timestamp_utc"])

    return {
        "attacker_ip": attacker_ip,
        "attack_start_epoch": start_epoch,
        "attack_end_epoch": end_epoch,
        "attack_family": attack_start.get("attack_family", ""),
        "attack_type": attack_start.get("attack_type", ""),
        "scenario_id": attack_start.get("scenario_id", ""),
        "run_id": attack_start.get("run_id", ""),
        "target_asset": attack_start.get("target_asset", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    gt_path = Path(args.ground_truth)
    output_path = Path(args.output)
    summary_path = Path(args.summary)

    gt = load_ground_truth(gt_path)

    normal_rows = 0
    attack_rows = 0
    attacker_to_target = 0
    target_to_attacker = 0
    background_during_attack = 0

    with input_path.open("r", encoding="utf-8-sig", newline="") as src:
        reader = csv.DictReader(src)

        extra_fields = [
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
        ]

        with output_path.open("w", encoding="utf-8", newline="") as dst:
            writer = csv.DictWriter(
                dst,
                fieldnames=list(reader.fieldnames or []) + extra_fields,
            )
            writer.writeheader()

            for row in reader:
                ts_text = (row.get("frame.time_epoch") or "").strip()
                src_ip = (row.get("ip.src") or "").strip()
                dst_ip = (row.get("ip.dst") or "").strip()

                try:
                    ts = float(ts_text)
                except ValueError:
                    ts = -1.0

                in_attack_window = (
                    gt["attack_start_epoch"]
                    <= ts
                    <= gt["attack_end_epoch"]
                )

                involves_attacker = (
                    src_ip == gt["attacker_ip"]
                    or dst_ip == gt["attacker_ip"]
                )

                is_attack = in_attack_window and involves_attacker

                if ts < gt["attack_start_epoch"]:
                    phase = "warmup"
                elif ts <= gt["attack_end_epoch"]:
                    phase = "attack"
                else:
                    phase = "recovery"

                if is_attack:
                    binary = "attack"
                    family = gt["attack_family"]
                    attack_type = gt["attack_type"]
                    attack_rows += 1

                    if src_ip == gt["attacker_ip"]:
                        direction = "attacker_to_target"
                        attacker_to_target += 1
                    else:
                        direction = "target_to_attacker"
                        target_to_attacker += 1
                else:
                    binary = "normal"
                    family = ""
                    attack_type = ""
                    normal_rows += 1

                    if in_attack_window and not involves_attacker:
                        direction = "background_during_attack"
                        background_during_attack += 1
                    else:
                        direction = "background"

                row.update(
                    {
                        "label_binary": binary,
                        "label_attack_family": family,
                        "label_attack_type": attack_type,
                        "label_phase": phase,
                        "label_is_attacker_traffic": int(involves_attacker),
                        "label_direction": direction,
                        "label_attacker_ip": gt["attacker_ip"],
                        "label_scenario_id": gt["scenario_id"],
                        "label_run_id": gt["run_id"],
                        "label_target_asset": gt["target_asset"],
                    }
                )

                writer.writerow(row)

    summary = {
        "run_id": gt["run_id"],
        "scenario_id": gt["scenario_id"],
        "attacker_ip": gt["attacker_ip"],
        "attack_start_epoch": gt["attack_start_epoch"],
        "attack_end_epoch": gt["attack_end_epoch"],
        "normal_rows": normal_rows,
        "attack_rows": attack_rows,
        "attacker_to_target_rows": attacker_to_target,
        "target_to_attacker_rows": target_to_attacker,
        "background_rows_during_attack_window": background_during_attack,
        "label_rule": (
            "attack iff packet timestamp is inside exact attack window "
            "and src/dst IP matches attacker IP"
        ),
    }

    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
