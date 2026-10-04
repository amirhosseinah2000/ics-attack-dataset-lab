#!/usr/bin/env python3
"""Reset the local Aloha Modbus Digital Twin to a reproducible baseline.

Safety scope:
- hard-coded target: aloha-plc
- hard-coded port: 5020
- intended to run only inside the project's Docker lab network

This helper is for lab housekeeping only. It should be called before capture
starts and after capture stops so reset traffic never contaminates a dataset.
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
    try:
        return method(device_id=UNIT_ID, **kwargs)
    except TypeError:
        return method(slave=UNIT_ID, **kwargs)


def main() -> int:
    ap = argparse.ArgumentParser(description="Reset local Aloha Modbus lab state")
    ap.add_argument("--tank-level", type=int, default=0)
    ap.add_argument("--settle-seconds", type=float, default=1.5)
    args = ap.parse_args()

    if not (0 <= args.tank_level <= 10000):
        raise SystemExit("--tank-level must be between 0 and 10000")
    if args.settle_seconds < 0:
        raise SystemExit("--settle-seconds must be >= 0")

    result: dict[str, Any] = {
        "timestamp_utc": utc_now(),
        "host": LAB_HOST,
        "port": LAB_PORT,
        "unit_id": UNIT_ID,
        "target_tank_level": args.tank_level,
        "success": False,
        "before": {},
        "after": {},
        "errors": [],
    }

    client = ModbusTcpClient(LAB_HOST, port=LAB_PORT, timeout=2.0)

    def read_coils(address: int, count: int):
        r = invoke(client.read_coils, address=address, count=count)
        if r.isError():
            raise RuntimeError(f"read_coils({address},{count}) failed: {r}")
        return [bool(v) for v in r.bits[:count]]

    def read_holding(address: int, count: int):
        r = invoke(client.read_holding_registers, address=address, count=count)
        if r.isError():
            raise RuntimeError(f"read_holding({address},{count}) failed: {r}")
        return [int(v) for v in r.registers[:count]]

    def write_coil(address: int, value: bool):
        r = invoke(client.write_coil, address=address, value=value)
        if r.isError():
            raise RuntimeError(f"write_coil({address},{value}) failed: {r}")

    def write_reg(address: int, value: int):
        r = invoke(client.write_register, address=address, value=value)
        if r.isError():
            raise RuntimeError(f"write_register({address},{value}) failed: {r}")

    try:
        if not client.connect():
            raise RuntimeError("could not connect to local Aloha PLC")

        coils = read_coils(0, 9)
        regs = read_holding(0, 10)
        result["before"] = {
            "tank_level": regs[0],
            "pump_switch": int(coils[1]),
            "inflow_mode": int(coils[5]),
            "inflow_rate": regs[6],
            "outflow_rate": regs[7],
            "overflow_alarm": int(coils[6]),
        }

        # Canonical idle controls. Tank level is a writable holding register in
        # Aloha and is used here only as an out-of-band lab reset.
        write_reg(6, 0)                 # InflowRate
        write_reg(7, 0)                 # OutflowRate
        write_coil(5, False)            # Auto mode
        write_coil(1, False)            # Pump off
        write_reg(0, args.tank_level)   # Canonical process baseline

        if args.settle_seconds:
            time.sleep(args.settle_seconds)

        coils2 = read_coils(0, 9)
        regs2 = read_holding(0, 10)
        result["after"] = {
            "tank_level": regs2[0],
            "pump_switch": int(coils2[1]),
            "inflow_mode": int(coils2[5]),
            "inflow_rate": regs2[6],
            "outflow_rate": regs2[7],
            "overflow_alarm": int(coils2[6]),
        }

        expected = {
            "tank_level": args.tank_level,
            "pump_switch": 0,
            "inflow_mode": 0,
            "inflow_rate": 0,
            "outflow_rate": 0,
        }
        mismatches = {
            k: {"expected": v, "actual": result["after"].get(k)}
            for k, v in expected.items()
            if result["after"].get(k) != v
        }
        if mismatches:
            result["errors"].append({"verification_mismatch": mismatches})
        else:
            result["success"] = True

    except Exception as exc:
        result["errors"].append(str(exc))
    finally:
        try:
            client.close()
        except Exception:
            pass

    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
