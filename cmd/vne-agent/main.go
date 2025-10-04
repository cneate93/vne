package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cneate93/vne/internal/logx"
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
	targetFlag := flag.String("target", "", "Target for WAN checks (default 1.1.1.1)")
	outFlag := flag.String("out", "", "Output HTML report path (default vne-report.html)")
	skipPythonFlag := flag.Bool("skip-python", false, "Skip the optional FortiGate Python pack")
	serveFlag := flag.Bool("serve", false, "Serve the generated report over HTTP on :8080")
	openFlag := flag.Bool("open", false, "Open the generated report after creation")
	pythonFlag := flag.String("python", "", "Path to python executable for the FortiGate pack")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging to vne.log")
	bundleFlag := flag.Bool("bundle", false, "Write zipped evidence bundle (vne-evidence-YYYYMMDD-HHMM.zip)")
	jsonFlag := flag.String("json", "", "Write report data as indented JSON to the given path")
	countFlag := flag.Int("count", 20, "Number of ping attempts for each host (default 20)")
	timeoutFlag := flag.Duration("timeout", 10*time.Second, "Timeout for network probes (default 10s)")
	flag.Parse()

	if err := logx.Configure(*verboseFlag); err != nil {
		fmt.Println("Unable to enable verbose logging:", err)
	} else if *verboseFlag {
		defer logx.Close()
	}

	flagsSet := map[string]bool{}
	flag.CommandLine.Visit(func(f *flag.Flag) {
		flagsSet[f.Name] = true
	})
	nonInteractive := flagsSet["target"] || flagsSet["out"] || flagsSet["skip-python"]

	fmt.Println("== Virtual Network Engineer (MVP) ==")

	ctx := RunContext{
		TargetHost: "1.1.1.1",
	}

	if *targetFlag != "" {
		ctx.TargetHost = *targetFlag
	}
	if *pythonFlag != "" {
		ctx.PythonPath = *pythonFlag
	}

	if nonInteractive {
		ctx.UserNotes = ""
	} else {
		ctx.UserNotes = prompt("Optional: describe the problem (e.g., 'Zoom choppy, started yesterday'):\n> ")

		th := prompt("Target for WAN checks (default 1.1.1.1): ")
		if th != "" {
			ctx.TargetHost = th
		}
	}

	log.Printf("Using target host: %s", ctx.TargetHost)

	if nonInteractive {
		if !*skipPythonFlag {
			log.Println("Skipping FortiGate Python pack in non-interactive mode; use interactive mode to supply credentials if needed.")
		}
	} else if *skipPythonFlag {
		fmt.Println("→ Skipping FortiGate Python pack (requested via --skip-python).")
	} else if yesno("Do you want to run the FortiGate Python pack (optional)?") {
		ctx.UsePythonFortigate = true
		ctx.FortiHost = prompt("FortiGate host/IP: ")
		ctx.FortiUser = prompt("FortiGate username: ")
		ctx.FortiPass = prompt("FortiGate password (will not be stored): ")
		if ctx.PythonPath == "" {
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
	}

	outPath := "vne-report.html"
	if *outFlag != "" {
		outPath = *outFlag
	}

	// 1) Local network info
	fmt.Println("\n→ Collecting local network info…")
	log.Println("Collecting local network info")
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
		log.Println("Pinging default gateway", gw)
		gwPing, _ = probes.PingHost(gw, *countFlag, *timeoutFlag)
	} else {
		fmt.Println("→ No default gateway detected; skipping gateway ping.")
		log.Println("No default gateway detected; skipping gateway ping")
	}

	// 3) DNS lookups
	fmt.Println("→ Testing DNS lookups…")
	log.Println("Testing DNS lookups")
	dnsLocal, _ := probes.DNSLookupTimed("cloudflare.com", netInfo.DNSServers, *timeoutFlag)
	dnsCF, _ := probes.DNSLookupTimed("cloudflare.com", []string{"1.1.1.1"}, *timeoutFlag)

	// 4) WAN ping/jitter
	fmt.Println("→ Pinging internet target:", ctx.TargetHost)
	log.Println("Pinging internet target", ctx.TargetHost)
	wanPing, _ := probes.PingHost(ctx.TargetHost, *countFlag, *timeoutFlag)

	// 5) Trace
	fmt.Println("→ Traceroute (this may take ~10–20 seconds)…")
	log.Println("Running traceroute")
	traceOut, _ := probes.Trace(ctx.TargetHost, 20, *timeoutFlag)

	// 6) MTU probe
	fmt.Println("→ MTU / Path MTU probe…")
	log.Println("Running MTU / Path MTU probe")
	mtu, _ := probes.MTUCheck(ctx.TargetHost)

	// 7) Optional FortiGate Python pack
	var fortiRaw map[string]any
	if ctx.UsePythonFortigate {
		fmt.Println("→ Running FortiGate Python pack…")
		log.Println("Running FortiGate Python pack")
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
	vpnAdapters := netInfo.VPNAdapterNames()
	if len(vpnAdapters) > 0 && (mtu.PathMTU == 0 || mtu.PathMTU < 1500) {
		mtuPhrase := "Path MTU probe was inconclusive"
		if mtu.PathMTU > 0 {
			mtuPhrase = fmt.Sprintf("Path MTU reported as %d", mtu.PathMTU)
		}
		findings = append(findings, report.Finding{
			Severity: "info",
			Message:  fmt.Sprintf("%s with active VPN/tunnel adapter (%s). Recommend setting tunnel MTU to 1420–1412 and enabling a TCP MSS clamp to avoid fragmentation.", mtuPhrase, strings.Join(vpnAdapters, ", ")),
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

	log.Println("Rendering HTML report to", outPath)
	if err := report.RenderHTML(res, "assets/report_template.html", outPath); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n✅ Done. Report written to:", outPath)
	log.Println("Report generation complete")

	if *jsonFlag != "" {
		jsonPath := *jsonFlag
		if err := writeJSONResults(jsonPath, res); err != nil {
			log.Fatalf("failed to write JSON results: %v", err)
		}
		fmt.Println("→ JSON results written to:", jsonPath)
		log.Println("JSON results written to", jsonPath)
	}

	if *bundleFlag {
		bundleName := fmt.Sprintf("vne-evidence-%s.zip", res.When.Format("20060102-1504"))
		rawFiles := map[string][]byte{
			"gateway-ping.txt": []byte(res.GwPing.Raw),
			"wan-ping.txt":     []byte(res.WanPing.Raw),
			"traceroute.txt":   []byte(res.Trace.Raw),
		}
		if err := report.WriteBundle(bundleName, res, rawFiles); err != nil {
			log.Fatalf("failed to write bundle: %v", err)
		}
		fmt.Println("→ Evidence bundle written to:", bundleName)
		log.Println("Evidence bundle written to", bundleName)
	}

	if *openFlag {
		absPath, err := filepath.Abs(outPath)
		if err != nil {
			log.Printf("Unable to resolve absolute path for %s: %v", outPath, err)
			absPath = outPath
		}

		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			cmd = exec.Command("cmd", "/c", "start", "", absPath)
		case "darwin":
			cmd = exec.Command("open", absPath)
		default:
			cmd = exec.Command("xdg-open", absPath)
		}

		fmt.Println("→ Opening report…")
		if err := cmd.Start(); err != nil {
			fmt.Println("Unable to open report:", err)
			log.Println("open report error:", err)
		}
	}

	if *serveFlag {
		relPath := outPath
		if filepath.IsAbs(relPath) {
			if p, err := filepath.Rel(".", relPath); err == nil {
				relPath = p
			}
		}
		relPath = filepath.ToSlash(relPath)
		parts := strings.Split(relPath, "/")
		for i, part := range parts {
			parts[i] = url.PathEscape(part)
		}
		servedPath := strings.Join(parts, "/")
		fmt.Printf("Serving report at http://localhost:8080/%s\n", servedPath)
		log.Fatal(http.ListenAndServe(":8080", http.FileServer(http.Dir("."))))
	}
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func writeJSONResults(jsonPath string, res report.Results) error {
	if dir := filepath.Dir(jsonPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	f, err := os.Create(jsonPath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return err
	}

	return nil
}
