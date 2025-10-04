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
	"github.com/cneate93/vne/internal/progress"
	"github.com/cneate93/vne/internal/report"
	"github.com/cneate93/vne/internal/webui"
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
	webFlag := flag.Bool("web", false, "Run embedded web UI on 127.0.0.1:8080")
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

	if *webFlag {
		srv, err := webui.NewServer(func(_ context.Context, req webui.RunRequest, reporter progress.Reporter) (report.Results, error) {
			runCtx := RunContext{
				TargetHost: "1.1.1.1",
				CiscoPort:  22,
			}
			if trimmed := strings.TrimSpace(req.Target); trimmed != "" {
				runCtx.TargetHost = trimmed
			}
			opts := RunOptions{
				Count:         *countFlag,
				Timeout:       *timeoutFlag,
				Scan:          req.Scan,
				ScanTimeout:   *scanTimeoutFlag,
				ScanMaxHosts:  *scanMaxHostsFlag,
				ScanCIDRLimit: *scanCIDRLimitFlag,
				SkipPython:    true,
				AutoPacks:     false,
				SNMPCfg:       nil,
				Printer:       newProgressPrinter(reporter),
				Progress:      reporter,
			}
			return runDiagnostics(runCtx, opts)
		})
		if err != nil {
			log.Fatal(err)
		}
		addr := "127.0.0.1:8080"
		fmt.Printf("Starting web UI at http://%s\n", addr)
		log.Println("Starting web UI server on", addr)
		if err := http.ListenAndServe(addr, srv); err != nil {
			log.Fatal(err)
		}
		return
	}

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

	res, err := runDiagnostics(ctx, RunOptions{
		Count:         *countFlag,
		Timeout:       *timeoutFlag,
		Scan:          *scanFlag,
		ScanTimeout:   *scanTimeoutFlag,
		ScanMaxHosts:  *scanMaxHostsFlag,
		ScanCIDRLimit: *scanCIDRLimitFlag,
		SkipPython:    *skipPythonFlag,
		AutoPacks:     autoPacksRequested,
		SNMPCfg:       snmpCfg,
		Printer:       stdPrinter{},
	})
	if err != nil {
		log.Fatal(err)
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
