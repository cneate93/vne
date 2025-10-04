package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cneate93/vne/internal/probes"
	"github.com/cneate93/vne/internal/report"
	"github.com/cneate93/vne/internal/sshx"
)

type RunContext struct {
	UserNotes          string
	TargetHost         string // default internet target
	UsePythonFortigate bool
	FortiHost          string
	FortiUser          string
	FortiPass          string
	PythonPath         string
}

func prompt(s string) string {
	fmt.Print(s)
	in := bufio.NewReader(os.Stdin)
	txt, _ := in.ReadString('\n')
	return strings.TrimSpace(txt)
}

func yesno(s string) bool {
	for {
		ans := strings.ToLower(prompt(s + " [y/n]: "))
		if ans == "y" || ans == "yes" {
			return true
		}
		if ans == "n" || ans == "no" {
			return false
		}
	}
}

func main() {
	fmt.Println("== Virtual Network Engineer (MVP) ==")

	ctx := RunContext{
		TargetHost: "1.1.1.1",
	}

	ctx.UserNotes = prompt("Optional: describe the problem (e.g., 'Zoom choppy, started yesterday'):\n> ")

	th := prompt("Target for WAN checks (default 1.1.1.1): ")
	if th != "" {
		ctx.TargetHost = th
	}

	if yesno("Do you want to run the FortiGate Python pack (optional)?") {
		ctx.UsePythonFortigate = true
		ctx.FortiHost = prompt("FortiGate host/IP: ")
		ctx.FortiUser = prompt("FortiGate username: ")
		ctx.FortiPass = prompt("FortiGate password (will not be stored): ")
		pp := prompt("Path to python executable (default 'python3' on macOS/Linux, 'python' on Windows): ")
		if pp == "" {
			if isWindows() {
				ctx.PythonPath = "python"
			} else {
				ctx.PythonPath = "python3"
			}
		} else {
			ctx.PythonPath = pp
		}
	}

	// 1) Local network info
	fmt.Println("\n→ Collecting local network info…")
	netInfo, err := probes.GetBasics()
	if err != nil {
		log.Println("netinfo error:", err)
	}

	// Determine gateway & DNS we’ll use
	gw := netInfo.DefaultGateway
	if gw == "" && len(netInfo.Gateways) > 0 {
		gw = netInfo.Gateways[0]
	}

	// 2) Gateway ping
	var gwPing probes.PingResult
	if gw != "" {
		fmt.Println("→ Pinging default gateway:", gw)
		gwPing, _ = probes.PingHost(gw, 10)
	} else {
		fmt.Println("→ No default gateway detected; skipping gateway ping.")
	}

	// 3) DNS lookups
	fmt.Println("→ Testing DNS lookups…")
	dnsLocal, _ := probes.DNSLookupTimed("cloudflare.com", netInfo.DNSServers)
	dnsCF, _ := probes.DNSLookupTimed("cloudflare.com", []string{"1.1.1.1"})

	// 4) WAN ping/jitter
	fmt.Println("→ Pinging internet target:", ctx.TargetHost)
	wanPing, _ := probes.PingHost(ctx.TargetHost, 20)

	// 5) Trace
	fmt.Println("→ Traceroute (this may take ~10–20 seconds)…")
	traceOut, _ := probes.Trace(ctx.TargetHost, 20)

	// 6) MTU probe
	fmt.Println("→ MTU / Path MTU probe…")
	mtu, _ := probes.MTUCheck(ctx.TargetHost)

	// 7) Optional FortiGate Python pack
	var fortiRaw map[string]any
	if ctx.UsePythonFortigate {
		fmt.Println("→ Running FortiGate Python pack…")
		packDir := filepath.Join("packs", "python", "fortigate")
		payload := map[string]any{
			"host":     ctx.FortiHost,
			"username": ctx.FortiUser,
			"password": ctx.FortiPass,
			"commands": map[string]string{
				"interfaces": "get hardware nic",
				"routes":     "get router info routing-table all",
			},
		}
		out, err := sshx.RunPythonPack(ctx.PythonPath, filepath.Join(packDir, "parser.py"), payload)
		if err != nil {
			log.Println("Forti pack error:", err)
		} else {
			_ = json.Unmarshal(out, &fortiRaw)
		}
	}

	// 8) Findings / heuristics (simple)
	var findings []report.Finding
	if gw != "" && gwPing.Loss > 0.3 {
		findings = append(findings, report.Finding{
			Severity: "high",
			Message:  fmt.Sprintf("High loss to default gateway (%.0f%%). Suspect local wiring/switch port; check cable/port; look for error counters.", gwPing.Loss*100),
		})
	}
	if dnsLocal.AvgMs > 100 && dnsCF.AvgMs > 0 && dnsCF.AvgMs < 50 {
		findings = append(findings, report.Finding{
			Severity: "medium",
			Message:  fmt.Sprintf("Local DNS slow (~%.0f ms). Consider using a public resolver (1.1.1.1) or fixing router DNS forwarder.", dnsLocal.AvgMs),
		})
	}
	if wanPing.Loss > 0.05 {
		findings = append(findings, report.Finding{
			Severity: "medium",
			Message:  fmt.Sprintf("Packet loss to internet target (~%.0f%%). Likely ISP/modem or upstream congestion.", wanPing.Loss*100),
		})
	}
	if mtu.PathMTU > 0 && mtu.PathMTU < 1500 {
		findings = append(findings, report.Finding{
			Severity: "info",
			Message:  fmt.Sprintf("Path MTU appears to be %d. If VPN/tunnel is in path, lower MTU or enable TCP MSS clamping.", mtu.PathMTU),
		})
	}

	// 9) Assemble report (pre-format loss % strings to keep template simple)
	res := report.Results{
		When:        time.Now(),
		UserNote:    ctx.UserNotes,
		NetInfo:     netInfo,
		GwPing:      gwPing,
		WanPing:     wanPing,
		DNSLocal:    dnsLocal,
		DNSCF:       dnsCF,
		Trace:       traceOut,
		MTU:         mtu,
		Findings:    findings,
		FortiRaw:    fortiRaw,
		GwLossPct:   fmt.Sprintf("%.0f%%", gwPing.Loss*100),
		WanLossPct:  fmt.Sprintf("%.0f%%", wanPing.Loss*100),
		TargetHost:  ctx.TargetHost,
		HasGateway:  gw != "",
		GatewayUsed: gw,
	}

	outPath := "vne-report.html"
	if err := report.RenderHTML(res, "assets/report_template.html", outPath); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n✅ Done. Report written to:", outPath)
}

func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows")
}
