# Architecture

```text
Scenario Runner
      |
      +---- Process Simulator (Aloha)
      |
      +---- Modbus PLC/HMI
      |
      +---- Capture Service
      |
      +---- Ground Truth Logger
      |
      +---- Dataset Builder
```

The first milestone intentionally separates:
- process simulation
- protocol traffic
- capture
- labels

This makes later protocol adapters (S7Comm, DNP3, IEC-104, etc.) easier to add.
