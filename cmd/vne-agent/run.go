package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/cneate93/vne/internal/engine"
	"github.com/cneate93/vne/internal/packs"
	"github.com/cneate93/vne/internal/progress"
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

type progressPrinter struct {
	sink progress.Reporter
}

func (stdPrinter) Println(args ...interface{}) {
	fmt.Println(args...)
}

func (stdPrinter) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (nopPrinter) Println(args ...interface{}) {}

func (nopPrinter) Printf(format string, args ...interface{}) {}

func newProgressPrinter(sink progress.Reporter) RunPrinter {
	if sink == nil {
		return nopPrinter{}
	}
	return &progressPrinter{sink: sink}
}

func (p *progressPrinter) Println(args ...interface{}) {
	if p == nil || p.sink == nil {
		return
	}
	msg := fmt.Sprintln(args...)
	p.forward(msg)
}

func (p *progressPrinter) Printf(format string, args ...interface{}) {
	if p == nil || p.sink == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	p.forward(msg)
}

func (p *progressPrinter) forward(msg string) {
	if p == nil || p.sink == nil {
		return
	}
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	lines := strings.Split(msg, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Preserve indentation from the original line while removing trailing carriage returns.
		p.sink.Step(strings.TrimRight(line, "\r"))
	}
}

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
	Progress      progress.Reporter
}

func runDiagnostics(ctx RunContext, opts RunOptions) (report.Results, error) {
	printer := opts.Printer
	if printer == nil {
		printer = nopPrinter{}
	}
	reporter := opts.Progress
	println := func(args ...interface{}) {
		printer.Println(args...)
	}
	printf := func(format string, args ...interface{}) {
		printer.Printf(format, args...)
	}
	phase := func(name string) {
		if reporter != nil {
			reporter.Phase(name)
		}
	}

	params := engine.Params{
		Count:         opts.Count,
		Timeout:       opts.Timeout,
		Scan:          opts.Scan,
		ScanTimeout:   opts.ScanTimeout,
		ScanMaxHosts:  opts.ScanMaxHosts,
		ScanCIDRLimit: opts.ScanCIDRLimit,
		TargetHost:    ctx.TargetHost,
		Reporter:      reporter,
		Printer:       printer,
	}
	baseRes, err := engine.Run(context.Background(), params)
	if err != nil {
		return report.Results{}, err
	}

	var autoPackFindings []report.Finding
	l2Hosts := baseRes.Discovered
	if opts.AutoPacks && !opts.SkipPython {
		phase("python-packs")
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
	} else if reporter != nil && !opts.SkipPython {
		phase("python-packs")
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
		phase("snmp")
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

	phase("finalizing")
	findings := append([]report.Finding{}, baseRes.Findings...)
	findings = append(findings, autoPackFindings...)
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

	baseRes.When = time.Now()
	baseRes.UserNote = ctx.UserNotes
	baseRes.Findings = findings
	baseRes.FortiRaw = fortiRaw
	baseRes.CiscoIOS = ciscoRaw
	baseRes.IfaceHealth = ifaceHealth
	baseRes.GwLossPct = fmt.Sprintf("%.0f%%", baseRes.GwPing.Loss*100)
	baseRes.WanLossPct = fmt.Sprintf("%.0f%%", baseRes.WanPing.Loss*100)

	return baseRes, nil
}
