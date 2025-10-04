# Virtual Network Engineer (MVP)
Cross-platform CLI that runs baseline network diagnostics (local info, ping, DNS timing, traceroute, MTU) and produces an HTML report. Optional Python FortiGate pack.

## Quick start
### macOS / Linux
```bash
git clone https://github.com/cneate93/vne.git
cd vne
# optional: build binaries for all platforms
make build
# interactive run
go run ./cmd/vne-agent
```

### Windows (PowerShell)
```powershell
git clone https://github.com/cneate93/vne.git
cd vne
# interactive run
go run .\cmd\vne-agent
```

The CLI writes `vne-report.html` by default. Pass `--serve` to expose the generated file on a temporary localhost web server and add `--open` to automatically launch your default browser after the report finishes rendering.

## CLI flags
| Flag | Description |
| ---- | ----------- |
| `--target <host>` | Override the default WAN target (`1.1.1.1`). |
| `--out <path>` | Set the output HTML report path. |
| `--skip-python` | Skip the optional FortiGate Python pack (non-interactive mode does this automatically). |
| `--python <path>` | Explicit path to the Python interpreter for the FortiGate pack. |
| `--serve` | Serve the generated report over HTTP after completion. |
| `--open` | Open the served report in the default browser (requires `--serve`). |

## Platform notes
- **macOS** – Requires Go 1.22+. The bundled `ping` and `traceroute` utilities are used; no extra permissions needed in most cases.
- **Linux** – Install `iputils-ping` and `traceroute` (or `tracepath`) if missing. Running the CLI as a non-root user is fine as long as those utilities are setuid/capability enabled.
- **Windows** – Works with Go 1.22+ and relies on the built-in `ping`/`tracert` commands. When prompted for FortiGate credentials, the CLI uses console input.

## Optional FortiGate pack prerequisites
- Python 3.10+
- [`netmiko`](https://github.com/ktbyers/netmiko)

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows
.\.venv\Scripts\Activate.ps1
pip install netmiko
```

## Troubleshooting
- **`exec: "traceroute": executable file not found`** – Install `traceroute` (macOS: `brew install inetutils`, Debian/Ubuntu: `sudo apt install traceroute`). On Linux the CLI will fall back to `tracepath` if available.
- **`ping: socket: Operation not permitted` / ICMP permission errors** – Ensure the system `ping` binary can send ICMP (Linux: `sudo apt install iputils-ping` and verify it has the `cap_net_raw` capability, or run the CLI with elevated privileges). Containers and minimal distros may require granting `CAP_NET_RAW` to the process.
- **FortiGate pack fails to launch** – Provide the correct Python interpreter with `--python` and verify `netmiko` is installed in that environment.
