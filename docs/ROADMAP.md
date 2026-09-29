# Roadmap

## M0 — Repository & specification
- [ ] Create GitHub repository
- [ ] Freeze directory structure
- [ ] Define dataset schema
- [ ] Define run/scenario IDs
- [ ] Define Git/data policy

## M1 — Modbus baseline lab
- [ ] Run MITRE Aloha Water Treatment
- [ ] Verify Modbus PLC/HMI connectivity
- [ ] Record normal traffic
- [ ] Save process-state telemetry

## M2 — Capture & ground truth
- [ ] Automated PCAP capture
- [ ] Run manifest
- [ ] Timestamp synchronization
- [ ] Ground-truth event format

## M3 — Scenario catalog
- [ ] Normal operating scenarios
- [ ] Read-only/recon scenarios
- [ ] Controlled state-change scenarios
- [ ] Availability/stress scenarios
- [ ] Map scenarios to ATT&CK for ICS where applicable

## M4 — Orchestration
- [ ] One-command scenario execution
- [ ] Reset simulator between runs
- [ ] Random seeds/parameter variation
- [ ] Repeat N runs

## M5 — Dataset builder
- [ ] PCAP index
- [ ] Flow metadata
- [ ] Packet labels
- [ ] Window labels
- [ ] Process-state joins

## M6 — QA
- [ ] PCAP integrity
- [ ] Timestamp/label consistency
- [ ] Protocol validation
- [ ] Duplicate detection
- [ ] Scenario balance report

## M7 — Modbus dataset v0.1
- [ ] Freeze train/validation/test
- [ ] Generate manifest/checksums
- [ ] Dataset card
- [ ] Baseline ML sanity test
