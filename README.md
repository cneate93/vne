# Virtual Network Engineer (MVP)

Cross-platform CLI that runs baseline network diagnostics (local info, ping, DNS timing, traceroute, MTU) and produces an HTML report. Optional Python FortiGate pack.

## Prerequisites
- Go 1.22+
- (Optional) Python 3.10+ with `netmiko` for the FortiGate pack:
  ```bash
  python -m venv .venv
  # macOS/Linux
  source .venv/bin/activate
  # Windows
  .\.venv\Scripts\Activate.ps1
  pip install netmiko
