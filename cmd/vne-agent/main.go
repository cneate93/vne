package main

import (
	"bufio"
	"context"
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
	"strconv"
	"strings"
	"time"

	"github.com/cneate93/vne/internal/logx"
	"github.com/cneate93/vne/internal/packs"
	"github.com/cneate93/vne/internal/probes"
	"github.com/cneate93/vne/internal/report"
	"github.com/cneate93/vne/internal/snmp"
	"github.com/cneate93/vne/internal/sshx"
)

type RunContext struct {
	UserNotes          string
	TargetHost         string // default internet target
	UsePythonFortigate bool
	UsePythonCisco     bool
	FortiHost          string
	FortiUser          string
	FortiPass          string
	PythonPath         string
	CiscoHost          string
	CiscoUser          string
	CiscoPass          string
	CiscoSecret        string
	CiscoPort          int
}

func prompt(s string) string {
	fmt.Print(s)
	in := bufio.NewReader(os.Stdin)
	txt, _ := in.ReadString('\n')
	return strings.TrimSpace(txt)
}

func defaultPythonPath() string {
	if isWindows() {
		return "python"
	}
	return "python3"
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

type snmpQuery struct {
	Host      string
	Community string
	Iface     string
}

func normalizeSNMPArgs() {
	args := os.Args[1:]
	var normalized []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--snmp" {
			j := i + 1
			var tokens []string
			for j < len(args) && !strings.HasPrefix(args[j], "-") {
				tokens = append(tokens, args[j])
				j++
			}
			if len(tokens) > 0 {
				normalized = append(normalized, "--snmp="+strings.Join(tokens, " "))
				i = j - 1
				continue
			}
		}
		normalized = append(normalized, args[i])
	}
	os.Args = append([]string{os.Args[0]}, normalized...)
}

func parseSNMPFlag(raw string) (*snmpQuery, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	fields := strings.Fields(raw)
	cfg := &snmpQuery{}
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("expected key=value pair, got %q", field)
		}
		key := strings.ToLower(parts[0])
		val := parts[1]
		switch key {
		case "host":
			cfg.Host = val
		case "community":
			cfg.Community = val
		case "if", "iface", "interface":
			cfg.Iface = val
		default:
			return nil, fmt.Errorf("unknown parameter %q", key)
		}
	}
	if cfg.Host == "" || cfg.Community == "" || cfg.Iface == "" {
		return nil, fmt.Errorf("host, community, and if parameters are required")
	}
	return cfg, nil
}

func main() {
	normalizeSNMPArgs()
	targetFlag := flag.String("target", "", "Target for WAN checks (default 1.1.1.1)")
	outFlag := flag.String("out", "", "Output HTML report path (default vne-report.html)")
	skipPythonFlag := flag.Bool("skip-python", false, "Skip optional Python packs (FortiGate, Cisco IOS)")
	serveFlag := flag.Bool("serve", false, "Serve the generated report over HTTP on :8080")
	openFlag := flag.Bool("open", false, "Open the generated report after creation")
	pythonFlag := flag.String("python", "", "Path to python executable for optional packs")
	autoPacksFlag := flag.Bool("auto-packs", false, "Automatically run vendor-specific packs when detected")
	scanFlag := flag.Bool("scan", false, "Enable layer-2 discovery ping sweep (experimental)")
	scanTimeoutFlag := flag.Duration("scan-timeout", 2*time.Second, "Timeout per host for layer-2 discovery (default 2s)")
	scanMaxHostsFlag := flag.Int("scan-max-hosts", 256, "Maximum number of layer-2 hosts to probe (default 256)")
	scanCIDRLimitFlag := flag.Int("scan-cidr-limit", 24, "Smallest CIDR mask to sweep (default 24)")
	fortiHostFlag := flag.String("forti-host", "", "FortiGate host/IP for optional Python pack")
	fortiUserFlag := flag.String("forti-user", "", "FortiGate username for optional Python pack")
	fortiPassFlag := flag.String("forti-pass", "", "FortiGate password for optional Python pack")
	ciscoHostFlag := flag.String("cisco-host", "", "Cisco IOS host/IP for optional Python pack")
	ciscoUserFlag := flag.String("cisco-user", "", "Cisco IOS username for optional Python pack")
	ciscoPassFlag := flag.String("cisco-pass", "", "Cisco IOS password for optional Python pack")
	ciscoSecretFlag := flag.String("cisco-secret", "", "Cisco IOS enable secret for optional Python pack")
	ciscoPortFlag := flag.Int("cisco-port", 22, "Cisco IOS SSH port (default 22)")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging to vne.log")
	bundleFlag := flag.Bool("bundle", false, "Write zipped evidence bundle (vne-evidence-YYYYMMDD-HHMM.zip)")
	jsonFlag := flag.String("json", "", "Write report data as indented JSON to the given path")
	countFlag := flag.Int("count", 20, "Number of ping attempts for each host (default 20)")
	timeoutFlag := flag.Duration("timeout", 10*time.Second, "Timeout for network probes (default 10s)")
	snmpFlag := flag.String("snmp", "", "SNMP interface query parameters, e.g. \"host=1.2.3.4 community=public if=Gig0/1\"")
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
	autoPacksRequested := *autoPacksFlag

	snmpCfg, err := parseSNMPFlag(*snmpFlag)
	if err != nil {
		fmt.Println("→ Unable to parse --snmp parameters:", err)
		log.Println("SNMP flag parse error:", err)
	}

	fmt.Println("== Virtual Network Engineer (MVP) ==")

	ctx := RunContext{
		TargetHost: "1.1.1.1",
		CiscoPort:  22,
	}

	ctx.FortiHost = stringFlagOrEnv(*fortiHostFlag, flagsSet["forti-host"], "FORTI_HOST", "FORTIGATE_HOST")
	ctx.FortiUser = stringFlagOrEnv(*fortiUserFlag, flagsSet["forti-user"], "FORTI_USER", "FORTIGATE_USER")
	ctx.FortiPass = stringFlagOrEnv(*fortiPassFlag, flagsSet["forti-pass"], "FORTI_PASS", "FORTI_PASSWORD", "FORTIGATE_PASS", "FORTIGATE_PASSWORD")
	ctx.CiscoHost = stringFlagOrEnv(*ciscoHostFlag, flagsSet["cisco-host"], "CISCO_HOST")
	ctx.CiscoUser = stringFlagOrEnv(*ciscoUserFlag, flagsSet["cisco-user"], "CISCO_USER")
	ctx.CiscoPass = stringFlagOrEnv(*ciscoPassFlag, flagsSet["cisco-pass"], "CISCO_PASS", "CISCO_PASSWORD")
	ctx.CiscoSecret = stringFlagOrEnv(*ciscoSecretFlag, flagsSet["cisco-secret"], "CISCO_SECRET")
	ctx.CiscoPort = intFlagOrEnv(ctx.CiscoPort, *ciscoPortFlag, flagsSet["cisco-port"], "CISCO_PORT")

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
	if snmpCfg != nil {
		log.Printf("SNMP query configured for host %s interface %s", snmpCfg.Host, snmpCfg.Iface)
	}

	if *skipPythonFlag {
		if nonInteractive {
			log.Println("Skipping optional Python packs (requested via --skip-python).")
		} else {
			fmt.Println("→ Skipping optional Python packs (requested via --skip-python).")
		}
	} else if !autoPacksRequested {
		if nonInteractive {
			log.Println("Skipping optional Python packs in non-interactive mode; use interactive mode to supply credentials if needed.")
		} else {
			if yesno("Do you want to run the FortiGate Python pack (optional)?") {
				ctx.UsePythonFortigate = true
				ctx.FortiHost = prompt("FortiGate host/IP: ")
				ctx.FortiUser = prompt("FortiGate username: ")
				ctx.FortiPass = prompt("FortiGate password (will not be stored): ")
			}
			if yesno("Do you want to run the Cisco IOS Python pack (optional)?") {
				ctx.UsePythonCisco = true
				ctx.CiscoHost = prompt("Cisco IOS host/IP: ")
				ctx.CiscoUser = prompt("Cisco IOS username: ")
				ctx.CiscoPass = prompt("Cisco IOS password (will not be stored): ")
				ctx.CiscoSecret = prompt("Cisco IOS enable secret (optional): ")
				portStr := prompt("Cisco IOS SSH port (default 22): ")
				if portStr != "" {
					if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
						ctx.CiscoPort = p
					} else {
						fmt.Println("  Invalid port provided; defaulting to 22.")
						ctx.CiscoPort = 22
					}
				}
			}
			if (ctx.UsePythonFortigate || ctx.UsePythonCisco) && ctx.PythonPath == "" {
				defPy := defaultPythonPath()
				promptMsg := fmt.Sprintf("Path to python executable (default '%s'): ", defPy)
				pp := prompt(promptMsg)
				if pp == "" {
					ctx.PythonPath = defPy
				} else {
					ctx.PythonPath = pp
				}
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

	// 1.5) Layer-2 discovery (ARP scan)
	var l2Hosts []probes.L2Host
	if *scanFlag {
		fmt.Println("→ Discovering local layer-2 neighbors (ping sweep)…")
		log.Println("Running layer-2 discovery")
		l2Hosts, l2Err := probes.L2Scan(*scanTimeoutFlag, *scanMaxHostsFlag, *scanCIDRLimitFlag)
		if l2Err != nil {
			fmt.Println("  Unable to complete L2 discovery:", l2Err)
			log.Println("L2 discovery error:", l2Err)
		} else if len(l2Hosts) == 0 {
			fmt.Println("  No L2 hosts discovered (ARP cache empty).")
		}
	} else {
		fmt.Println("→ Skipping local layer-2 discovery (enable with --scan).")
		log.Println("Skipping layer-2 discovery (flag not set)")
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

	var autoPackFindings []report.Finding
	if autoPacksRequested && !*skipPythonFlag {
		selected := packs.PacksFor(l2Hosts)
		if len(selected) > 0 {
			log.Printf("Auto-selected vendor packs: %v", selected)
		}
		for _, key := range selected {
			switch key {
			case "fortigate":
				if ctx.FortiHost != "" && ctx.FortiUser != "" && ctx.FortiPass != "" {
					ctx.UsePythonFortigate = true
				} else {
					autoPackFindings = append(autoPackFindings, report.Finding{
						Severity: "info",
						Message:  "Detected Fortinet device(s): supply --forti-host, --forti-user, and --forti-pass to run vendor pack.",
					})
					log.Println("Detected Fortinet device(s) but missing FortiGate credentials; skipping auto pack run.")
				}
			case "cisco_ios":
				if ctx.CiscoHost != "" && ctx.CiscoUser != "" && ctx.CiscoPass != "" {
					ctx.UsePythonCisco = true
				} else {
					autoPackFindings = append(autoPackFindings, report.Finding{
						Severity: "info",
						Message:  "Detected Cisco device(s): supply --cisco-host, --cisco-user, and --cisco-pass to run vendor pack.",
					})
					log.Println("Detected Cisco device(s) but missing Cisco IOS credentials; skipping auto pack run.")
				}
			}
		}
		if (ctx.UsePythonFortigate || ctx.UsePythonCisco) && ctx.PythonPath == "" {
			ctx.PythonPath = defaultPythonPath()
		}
	}

	// 7) Optional FortiGate Python pack
	var fortiRaw map[string]any
	var ciscoRaw *report.CiscoPackResults
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

	if ctx.UsePythonCisco {
		fmt.Println("→ Running Cisco IOS Python pack…")
		log.Println("Running Cisco IOS Python pack")
		packDir := filepath.Join("packs", "python", "cisco_ios")
		payload := map[string]any{
			"host":     ctx.CiscoHost,
			"username": ctx.CiscoUser,
			"password": ctx.CiscoPass,
		}
		if ctx.CiscoSecret != "" {
			payload["secret"] = ctx.CiscoSecret
		}
		if ctx.CiscoPort != 0 && ctx.CiscoPort != 22 {
			payload["port"] = ctx.CiscoPort
		}
		out, err := sshx.RunPythonPack(ctx.PythonPath, filepath.Join(packDir, "parser.py"), payload)
		if err != nil {
			log.Println("Cisco IOS pack error:", err)
		} else {
			var parsed report.CiscoPackResults
			if err := json.Unmarshal(out, &parsed); err != nil {
				log.Println("Cisco IOS pack parse error:", err)
			} else {
				ciscoRaw = &parsed
			}
		}
	}

	// 7.5) Optional SNMP interface health
	var ifaceHealth *snmp.InterfaceHealth
	if snmpCfg != nil {
		fmt.Println("\n→ Fetching SNMP interface health…")
		log.Printf("Fetching SNMP interface health from %s (%s)", snmpCfg.Host, snmpCfg.Iface)
		snmpCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ifaceHealth, err = snmp.GetInterfaceHealth(snmpCtx, snmpCfg.Host, snmpCfg.Community, snmpCfg.Iface)
		cancel()
		if err != nil {
			fmt.Println("  Unable to fetch interface health:", err)
			log.Println("SNMP interface health error:", err)
		} else {
			fmt.Printf("  Interface %s status: %s\n", ifaceHealth.Name, ifaceHealth.OperStatus)
			fmt.Printf("  Speed: %d bps\n", ifaceHealth.SpeedBps)
			fmt.Printf("  InErrors=%d OutErrors=%d InDiscards=%d OutDiscards=%d\n",
				ifaceHealth.InErrors, ifaceHealth.OutErrors, ifaceHealth.InDiscards, ifaceHealth.OutDiscards)
		}
	}

	// 8) Findings / heuristics (simple)
	var findings []report.Finding
	findings = append(findings, autoPackFindings...)
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
	if ifaceHealth != nil {
		if ifaceHealth.OperStatus != "" && strings.ToLower(ifaceHealth.OperStatus) != "up" {
			findings = append(findings, report.Finding{
				Severity: "high",
				Message:  fmt.Sprintf("Interface %s reports operational status %s via SNMP.", ifaceHealth.Name, ifaceHealth.OperStatus),
			})
		}
		if ifaceHealth.InErrors > 0 || ifaceHealth.OutErrors > 0 {
			findings = append(findings, report.Finding{
				Severity: "medium",
				Message:  fmt.Sprintf("Interface %s shows %d input and %d output errors via SNMP.", ifaceHealth.Name, ifaceHealth.InErrors, ifaceHealth.OutErrors),
			})
		}
		if ifaceHealth.InDiscards > 0 || ifaceHealth.OutDiscards > 0 {
			findings = append(findings, report.Finding{
				Severity: "medium",
				Message:  fmt.Sprintf("Interface %s shows %d input and %d output discards via SNMP.", ifaceHealth.Name, ifaceHealth.InDiscards, ifaceHealth.OutDiscards),
			})
		}
	}
	if ciscoRaw != nil {
		findings = append(findings, ciscoRaw.Findings...)
	}

	// 9) Assemble report (pre-format loss % strings to keep template simple)
	res := report.Results{
		When:        time.Now(),
		UserNote:    ctx.UserNotes,
		NetInfo:     netInfo,
		Discovered:  l2Hosts,
		GwPing:      gwPing,
		WanPing:     wanPing,
		DNSLocal:    dnsLocal,
		DNSCF:       dnsCF,
		Trace:       traceOut,
		MTU:         mtu,
		Findings:    findings,
		FortiRaw:    fortiRaw,
		CiscoIOS:    ciscoRaw,
		IfaceHealth: ifaceHealth,
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

	servedURL := ""
	if *serveFlag {
		servedURL = buildServedURL(outPath)
		fmt.Printf("Serving report at %s\n", servedURL)
		log.Println("Serving report at", servedURL)
		serverErr := make(chan error, 1)
		go func() {
			serverErr <- http.ListenAndServe(":8080", http.FileServer(http.Dir(".")))
		}()

		if *openFlag {
			fmt.Println("→ Opening report in browser…")
			go func(url string) {
				time.Sleep(200 * time.Millisecond)
				if err := openInBrowser(url); err != nil {
					fmt.Println("Unable to open report:", err)
					log.Println("open report error:", err)
				}
			}(servedURL)
		}

		log.Fatal(<-serverErr)
	} else if *openFlag {
		fmt.Println("→ --open requires --serve; ignoring.")
		log.Println("--open requested without --serve; ignoring")
	}
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func buildServedURL(outPath string) string {
	relPath := outPath
	if filepath.IsAbs(relPath) {
		if p, err := filepath.Rel(".", relPath); err == nil {
			relPath = p
		}
	}
	if relPath == "." {
		relPath = ""
	}
	relPath = filepath.ToSlash(relPath)
	parts := strings.Split(relPath, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	servedPath := strings.Join(parts, "/")
	if servedPath == "" {
		return "http://localhost:8080/"
	}
	return "http://localhost:8080/" + servedPath
}

func openInBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
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

func stringFlagOrEnv(flagVal string, flagSet bool, envKeys ...string) string {
	val := strings.TrimSpace(flagVal)
	if flagSet {
		return val
	}
	if val != "" {
		return val
	}
	for _, key := range envKeys {
		if key == "" {
			continue
		}
		if envVal := strings.TrimSpace(os.Getenv(key)); envVal != "" {
			return envVal
		}
	}
	return ""
}

func intFlagOrEnv(defaultVal, flagVal int, flagSet bool, envKeys ...string) int {
	if flagSet {
		if flagVal > 0 {
			return flagVal
		}
		return defaultVal
	}
	for _, key := range envKeys {
		if key == "" {
			continue
		}
		if envVal := strings.TrimSpace(os.Getenv(key)); envVal != "" {
			if parsed, err := strconv.Atoi(envVal); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	if flagVal > 0 {
		return flagVal
	}
	return defaultVal
}
