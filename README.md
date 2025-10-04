# Virtual Network Engineer (MVP)
Cross-platform CLI that runs baseline network diagnostics (local info, ping, DNS timing, traceroute, MTU) and produces an HTML report. Optional Python FortiGate and Cisco IOS packs.

## Quick start
### macOS / Linux
```bash
git clone https://github.com/cneate93/vne.git
cd vne
# optional: build binaries for all platforms
make build
# run and open the report in your browser
go run ./cmd/vne-agent --serve --open
```

If you prefer to open the HTML manually, the report is written to `./vne-report.html`. Use `open vne-report.html` on macOS or `xdg-open vne-report.html` (or `wslview` under WSL) on Linux.

### Windows (PowerShell)
```powershell
git clone https://github.com/cneate93/vne.git
cd vne
# run and open the report in your browser
go run .\cmd\vne-agent --serve --open
```

The Windows report is saved as `.\vne-report.html`. Launch it manually with `start .\vne-report.html` if you do not use `--serve --open`.

## CLI flags
| Flag | Description |
| ---- | ----------- |
| `--target <host>` | Override the default WAN target (`1.1.1.1`). |
| `--out <path>` | Set the output HTML report path. |
| `--skip-python` | Skip the optional Python packs (non-interactive mode does this automatically). |
| `--python <path>` | Explicit path to the Python interpreter for the optional packs. |
| `--serve` | Serve the generated report over HTTP after completion. |
| `--open` | Open the served report in the default browser (requires `--serve`). |

## Platform notes
- **macOS** – Requires Go 1.22+. The bundled `ping` and `traceroute` utilities are used; no extra permissions needed in most cases.
- **Linux** – Install `iputils-ping` and `traceroute` (or `tracepath`) if missing. Running the CLI as a non-root user is fine as long as those utilities are setuid/capability enabled.
- **Windows** – Works with Go 1.22+ and relies on the built-in `ping`/`tracert` commands. When prompted for optional Python pack credentials, the CLI uses console input.

## Optional Python pack prerequisites
- Python 3.10+
- [`netmiko`](https://github.com/ktbyers/netmiko)
- [`textfsm`](https://github.com/google/textfsm)

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows
.\.venv\Scripts\Activate.ps1
pip install netmiko textfsm
```

## Troubleshooting
- **`exec: "traceroute": executable file not found`** – Install `traceroute` (macOS: `brew install inetutils`; Debian/Ubuntu: `sudo apt install traceroute`; RHEL/CentOS/Fedora: `sudo dnf install traceroute`). On Linux the CLI will fall back to `tracepath` if available.
- **`exec: "ping": executable file not found`** – Install the platform ping package (Debian/Ubuntu: `sudo apt install iputils-ping`; RHEL/CentOS/Fedora: `sudo dnf install iputils`; Alpine: `sudo apk add iputils`). Windows and macOS ship with ping by default.
- **`ping: socket: Operation not permitted` / ICMP permission errors** – Ensure the system `ping` binary can send ICMP. On Linux, verify it carries `cap_net_raw` (`getcap $(command -v ping)`), reapply it if necessary (`sudo setcap cap_net_raw+ep $(command -v ping)`), or run the CLI with elevated privileges. Containers and minimal distros may require adding the `CAP_NET_RAW` capability to the runtime.
- **Python pack fails to launch** – Provide the correct Python interpreter with `--python` and verify `netmiko` and `textfsm` are installed in that environment.
