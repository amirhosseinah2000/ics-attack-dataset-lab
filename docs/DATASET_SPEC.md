# Dataset Specification v0.1

Each run must produce or reference:

- `traffic.pcap`
- `ground_truth.jsonl`
- `process_state.csv` or Parquet
- `manifest.yaml`

## Required manifest fields
- dataset_version
- run_id
- scenario_id
- protocol
- simulator
- tool_versions
- start_time_utc
- end_time_utc
- random_seed
- topology
- capture_interface
- fidelity_level

## Initial label hierarchy
1. Binary: normal / attack
2. Attack family
3. Attack type
4. Protocol operation
5. Physical impact
6. Success/failure

Labels must be derivable at packet, flow, and time-window level where technically meaningful.
