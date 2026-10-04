#!/usr/bin/env python3
import argparse
import json
import time
from datetime import datetime, timezone

from pymodbus.client import ModbusTcpClient


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Controlled Modbus read-only reconnaissance for the local Aloha lab."
    )
    parser.add_argument("--host", default="aloha-plc", choices=["aloha-plc", "localhost", "127.0.0.1", "::1"],
                        help="Version 1 is restricted to the local Docker Digital Twin.")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--unit-id", type=int, default=1)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--rate", type=float, default=5.0)
    parser.add_argument("--holding-address", type=int, default=0)
    parser.add_argument("--holding-count", type=int, default=10)
    parser.add_argument("--coil-address", type=int, default=0)
    parser.add_argument("--coil-count", type=int, default=9)
    args = parser.parse_args()

    interval = 1.0 / max(args.rate, 0.1)

    stats = {
        "started_utc": utc_now(),
        "ended_utc": None,
        "host": args.host,
        "port": args.port,
        "unit_id": args.unit_id,
        "duration_seconds": args.duration,
        "requests_per_second": args.rate,
        "holding_reads_attempted": 0,
        "holding_reads_ok": 0,
        "coil_reads_attempted": 0,
        "coil_reads_ok": 0,
        "errors": 0,
    }

    client = ModbusTcpClient(args.host, port=args.port, timeout=2.0)
    if not client.connect():
        stats["errors"] += 1
        stats["ended_utc"] = utc_now()
        print(json.dumps(stats))
        return 2

    deadline = time.monotonic() + args.duration

    try:
        while time.monotonic() < deadline:
            cycle_start = time.monotonic()

            try:
                stats["holding_reads_attempted"] += 1
                result = client.read_holding_registers(
                    address=args.holding_address,
                    count=args.holding_count,
                    device_id=args.unit_id,
                )
                if not result.isError():
                    stats["holding_reads_ok"] += 1
                else:
                    stats["errors"] += 1
            except Exception:
                stats["errors"] += 1

            try:
                stats["coil_reads_attempted"] += 1
                result = client.read_coils(
                    address=args.coil_address,
                    count=args.coil_count,
                    device_id=args.unit_id,
                )
                if not result.isError():
                    stats["coil_reads_ok"] += 1
                else:
                    stats["errors"] += 1
            except Exception:
                stats["errors"] += 1

            elapsed = time.monotonic() - cycle_start
            time.sleep(max(0.0, interval - elapsed))
    finally:
        client.close()

    stats["ended_utc"] = utc_now()
    print(json.dumps(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
