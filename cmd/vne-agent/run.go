package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/cneate93/vne/internal/packs"
	"github.com/cneate93/vne/internal/probes"
	"github.com/cneate93/vne/internal/report"
	"github.com/cneate93/vne/internal/snmp"
	"github.com/cneate93/vne/internal/sshx"
)

type RunPrinter interface {
	Println(...interface{})
	Printf(string, ...interface{})
}

type stdPrinter struct{}

type nopPrinter struct{}

func (stdPrinter) Println(args ...interface{}) {
	fmt.Println(args...)
}

func (stdPrinter) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (nopPrinter) Println(args ...interface{}) {}

func (nopPrinter) Printf(format string, args ...interface{}) {}

type RunOptions struct {
	Count         int
	Timeout       time.Duration
	Scan          bool
	ScanTimeout   time.Duration
	ScanMaxHosts  int
	ScanCIDRLimit int
	SkipPython    bool
	AutoPacks     bool
	SNMPCfg       *snmpQuery
	Printer       RunPrinter
}

func runDiagnostics(ctx RunContext, opts RunOptions) (report.Results, error) {
	printer := opts.Printer
	if printer == nil {
		printer = nopPrinter{}
	}
	println := func(args ...interface{}) {
		printer.Println(args...)
	}
	printf := func(format string, args ...interface{}) {
		printer.Printf(format, args...)
	}

	println("\n→ Collecting local network info…")
	log.Println("Collecting local network info")
	netInfo, err := probes.GetBasics()
	if err != nil {
		log.Println("netinfo error:", err)
	}

	gw := netInfo.DefaultGateway
	if gw == "" && len(netInfo.Gateways) > 0 {
		gw = netInfo.Gateways[0]
	}

	var l2Hosts []probes.L2Host
	if opts.Scan {
		println("→ Discovering local layer-2 neighbors (ping sweep)…")
		log.Println("Running layer-2 discovery")
		l2Hosts, err = probes.L2Scan(opts.ScanTimeout, opts.ScanMaxHosts, opts.ScanCIDRLimit)
		if err != nil {
			println("  Unable to complete L2 discovery:", err)
			log.Println("L2 discovery error:", err)
		} else if len(l2Hosts) == 0 {
			println("  No L2 hosts discovered (ARP cache empty).")
		}
	} else {
		println("→ Skipping local layer-2 discovery (enable with --scan).")
		log.Println("Skipping layer-2 discovery (flag not set)")
	}

	var gwPing probes.PingResult
	if gw != "" {
		println("→ Pinging default gateway:", gw)
		log.Println("Pinging default gateway", gw)
		gwPing, _ = probes.PingHost(gw, opts.Count, opts.Timeout)
	} else {
		println("→ No default gateway detected; skipping gateway ping.")
		log.Println("No default gateway detected; skipping gateway ping")
	}

	println("→ Testing DNS lookups…")
	log.Println("Testing DNS lookups")
	dnsLocal, _ := probes.DNSLookupTimed("cloudflare.com", netInfo.DNSServers, opts.Timeout)
	dnsCF, _ := probes.DNSLookupTimed("cloudflare.com", []string{"1.1.1.1"}, opts.Timeout)

	println("→ Pinging internet target:", ctx.TargetHost)
	log.Println("Pinging internet target", ctx.TargetHost)
	wanPing, _ := probes.PingHost(ctx.TargetHost, opts.Count, opts.Timeout)

	println("→ Traceroute (this may take ~10–20 seconds)…")
	log.Println("Running traceroute")
	traceOut, _ := probes.Trace(ctx.TargetHost, 20, opts.Timeout)

	println("→ MTU / Path MTU probe…")
	log.Println("Running MTU / Path MTU probe")
	mtu, _ := probes.MTUCheck(ctx.TargetHost)

	var autoPackFindings []report.Finding
	if opts.AutoPacks && !opts.SkipPython {
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

	var fortiRaw map[string]any
	var ciscoRaw *report.CiscoPackResults
	if !opts.SkipPython && ctx.UsePythonFortigate {
		println("→ Running FortiGate Python pack…")
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
		parserPath := filepath.Join(packDir, "parser.py")
		out, err := sshx.RunPythonPack(ctx.PythonPath, parserPath, payload)
		if err != nil {
			log.Println("Forti pack error:", err)
		} else {
			_ = json.Unmarshal(out, &fortiRaw)
		}
	}

	if !opts.SkipPython && ctx.UsePythonCisco {
		println("→ Running Cisco IOS Python pack…")
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
		parserPath := filepath.Join(packDir, "parser.py")
		out, err := sshx.RunPythonPack(ctx.PythonPath, parserPath, payload)
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

	var ifaceHealth *snmp.InterfaceHealth
	if opts.SNMPCfg != nil {
		println("\n→ Fetching SNMP interface health…")
		log.Printf("Fetching SNMP interface health from %s (%s)", opts.SNMPCfg.Host, opts.SNMPCfg.Iface)
		snmpCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ifaceHealth, err = snmp.GetInterfaceHealth(snmpCtx, opts.SNMPCfg.Host, opts.SNMPCfg.Community, opts.SNMPCfg.Iface)
		if err != nil {
			println("  Unable to fetch interface health:", err)
			log.Println("SNMP interface health error:", err)
		} else {
			printf("  Interface %s status: %s\n", ifaceHealth.Name, ifaceHealth.OperStatus)
			printf("  Speed: %d bps\n", ifaceHealth.SpeedBps)
			printf("  InErrors=%d OutErrors=%d InDiscards=%d OutDiscards=%d\n",
				ifaceHealth.InErrors, ifaceHealth.OutErrors, ifaceHealth.InDiscards, ifaceHealth.OutDiscards)
		}
	}

	findings := append([]report.Finding{}, autoPackFindings...)
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

	return res, nil
}
