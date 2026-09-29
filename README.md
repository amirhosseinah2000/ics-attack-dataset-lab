# ICS Attack Dataset Lab

A reproducible lab for generating labelled industrial-network datasets.

## Phase 1
Modbus/TCP using MITRE Aloha Water Treatment as the first process simulator.

## Design goals
- Reproducible scenario runs
- Raw PCAP retention
- Ground-truth timestamps
- Packet/flow/window-ready labels
- Clear provenance and tool versions
- No large generated datasets committed to Git

## Initial architecture

Process Simulator -> Modbus PLC/HMI -> Capture -> Ground Truth -> Dataset Builder

Attack tooling is integrated only inside an isolated lab environment.

## Repository policy
Commit:
- source code
- configuration
- scenario definitions
- tests
- documentation
- manifests/checksums

Do not commit:
- PCAP datasets
- generated CSV/Parquet outputs
- virtual machines
- secrets
- temporary captures
