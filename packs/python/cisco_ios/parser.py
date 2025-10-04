import json
import sys
from pathlib import Path

from netmiko import ConnectHandler
from textfsm import TextFSM


def load_template(name: str) -> TextFSM:
    template_path = Path(__file__).with_name("templates") / f"{name}.textfsm"
    with template_path.open("r", encoding="utf-8") as fh:
        return TextFSM(fh)


def parse_show_interfaces(output: str) -> list[dict[str, object]]:
    fsm = load_template("show_interfaces")
    records = []
    for row in fsm.ParseText(output):
        data = dict(zip(fsm.header, row))
        iface = data.get("INTERFACE", "")
        duplex = data.get("DUPLEX", "")
        speed_raw = data.get("SPEED", "")
        digits = "".join(ch for ch in speed_raw if ch.isdigit())
        speed = f"{digits}Mbps" if digits else speed_raw
        crc = int(data.get("CRC", 0) or 0)
        input_errs = int(data.get("INPUT_ERRS", 0) or 0)
        output_errs = int(data.get("OUTPUT_ERRS", 0) or 0)
        records.append(
            {
                "iface": iface,
                "duplex": duplex.lower(),
                "speed": speed,
                "crc": crc,
                "input_errs": input_errs,
                "output_errs": output_errs,
            }
        )
    return records


def build_findings(interfaces: list[dict[str, object]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for iface in interfaces:
        name = iface.get("iface", "unknown")
        duplex = str(iface.get("duplex", "")).lower()
        input_errs = int(iface.get("input_errs", 0) or 0)
        output_errs = int(iface.get("output_errs", 0) or 0)
        crc = int(iface.get("crc", 0) or 0)
        if duplex.startswith("half"):
            findings.append(
                {
                    "severity": "medium",
                    "message": f"Interface {name} is operating in half-duplex mode.",
                }
            )
        if input_errs > 0 or output_errs > 0 or crc > 0:
            findings.append(
                {
                    "severity": "medium",
                    "message": (
                        f"Interface {name} reports errors (input={input_errs}, "
                        f"output={output_errs}, crc={crc})."
                    ),
                }
            )
    return findings


def main() -> None:
    payload = json.load(sys.stdin)
    host = payload["host"]
    username = payload["username"]
    password = payload.get("password", "")
    secret = payload.get("secret", "")
    port = int(payload.get("port", 22) or 22)

    device = {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "secret": secret,
        "port": port,
        "fast_cli": False,
    }

    conn = ConnectHandler(**device)
    try:
        if secret:
            conn.enable()
        interfaces_raw = conn.send_command("show interfaces", use_textfsm=False)
    finally:
        conn.disconnect()

    interfaces = parse_show_interfaces(interfaces_raw)
    findings = build_findings(interfaces)

    result = {
        "interfaces": interfaces,
        "findings": findings,
        "raw": interfaces_raw,
    }
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
