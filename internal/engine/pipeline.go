package engine

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cneate93/vne/internal/probes"
	"github.com/cneate93/vne/internal/progress"
	"github.com/cneate93/vne/internal/report"
)

type Printer interface {
	Println(...interface{})
	Printf(string, ...interface{})
}

type Params struct {
	Count         int
	Timeout       time.Duration
	Scan          bool
	ScanTimeout   time.Duration
	ScanMaxHosts  int
	ScanCIDRLimit int
	TargetHost    string
	DNSTarget     string
	Reporter      progress.Reporter
	Printer       Printer
}

type noopPrinter struct{}

func (noopPrinter) Println(...interface{})        {}
func (noopPrinter) Printf(string, ...interface{}) {}

func Run(ctx context.Context, params Params) (report.Results, error) {
	reporter := params.Reporter
	printer := params.Printer
	if printer == nil {
		printer = noopPrinter{}
	}

	count := params.Count
	if count <= 0 {
		count = 4
	}
	timeout := params.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	scanTimeout := params.ScanTimeout
	if scanTimeout <= 0 {
		scanTimeout = 30 * time.Second
	}
	maxHosts := params.ScanMaxHosts
	if maxHosts <= 0 {
		maxHosts = 256
	}
	cidrLimit := params.ScanCIDRLimit
	if cidrLimit <= 0 {
		cidrLimit = 24
	}
	target := strings.TrimSpace(params.TargetHost)
	if target == "" {
		target = "1.1.1.1"
	}
	dnsTarget := strings.TrimSpace(params.DNSTarget)
	if dnsTarget == "" {
		dnsTarget = "cloudflare.com"
	}

	phase := func(name string) {
		if reporter != nil {
			reporter.Phase(name)
		}
	}
	step := func(msg string) {
		if reporter != nil {
			reporter.Step(msg)
		}
	}
	checkCtx := func() error {
		if ctx == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	var (
		netInfo  probes.NetInfo
		l2Hosts  []probes.L2Host
		gwPing   probes.PingResult
		wanPing  probes.PingResult
		dnsLocal probes.DNSResult
		dnsCF    probes.DNSResult
		traceOut probes.TraceResult
		mtu      probes.MTUResult
	)

	phase("netinfo")
	step("\n→ Collecting local network info…")
	log.Println("Collecting local network info")
	printer.Println("\n→ Collecting local network info…")
	if err := checkCtx(); err != nil {
		return report.Results{}, err
	}
	if info, err := probes.GetBasics(); err == nil {
		netInfo = info
	} else {
		printer.Println("  Unable to gather netinfo:", err)
		log.Println("netinfo error:", err)
	}

	gw := netInfo.DefaultGateway
	if gw == "" && len(netInfo.Gateways) > 0 {
		gw = netInfo.Gateways[0]
	}

	phase("l2-scan")
	if params.Scan {
		step("→ Discovering local layer-2 neighbors (ping sweep)…")
		printer.Println("→ Discovering local layer-2 neighbors (ping sweep)…")
		log.Println("Running layer-2 discovery")
		if err := checkCtx(); err != nil {
			return report.Results{}, err
		}
		if hosts, err := probes.L2Scan(ctx, scanTimeout, maxHosts, cidrLimit); err == nil {
			l2Hosts = hosts
			if len(l2Hosts) == 0 {
				printer.Println("  No L2 hosts discovered (ARP cache empty).")
			}
		} else {
			printer.Println("  Unable to complete L2 discovery:", err)
			log.Println("L2 discovery error:", err)
		}
	} else {
		step("→ Skipping local layer-2 discovery (enable with --scan).")
		printer.Println("→ Skipping local layer-2 discovery (enable with --scan).")
		log.Println("Skipping layer-2 discovery (flag not set)")
	}

	phase("gateway")
	if err := checkCtx(); err != nil {
		return report.Results{}, err
	}
	if gw != "" {
		msg := fmt.Sprintf("→ Pinging default gateway: %s", gw)
		step(msg)
		printer.Println(msg)
		var err error
		gwPing, err = probes.PingHost(gw, count, timeout)
		if err != nil {
			printer.Println("  Gateway ping error:", err)
			log.Println("Gateway ping error:", err)
		}
	} else {
		step("→ No default gateway detected; skipping gateway ping.")
		printer.Println("→ No default gateway detected; skipping gateway ping.")
		log.Println("No default gateway detected; skipping gateway ping")
	}

	phase("dns")
	step("→ Testing DNS lookups…")
	printer.Println("→ Testing DNS lookups…")
	log.Println("Testing DNS lookups")
	if err := checkCtx(); err != nil {
		return report.Results{}, err
	}
	dnsLocal, _ = probes.DNSLookupTimed(dnsTarget, netInfo.DNSServers, timeout)
	dnsCF, _ = probes.DNSLookupTimed(dnsTarget, []string{"1.1.1.1"}, timeout)

	phase("wan")
	msg := fmt.Sprintf("→ Pinging internet target: %s", target)
	step(msg)
	printer.Println(msg)
	log.Println("Pinging internet target", target)
	if err := checkCtx(); err != nil {
		return report.Results{}, err
	}
	var err error
	wanPing, err = probes.PingHost(target, count, timeout)
	if err != nil {
		printer.Println("  WAN ping error:", err)
		log.Println("WAN ping error:", err)
	}

	phase("traceroute")
	step("→ Traceroute (this may take ~10–20 seconds)…")
	printer.Println("→ Traceroute (this may take ~10–20 seconds)…")
	log.Println("Running traceroute")
	if err := checkCtx(); err != nil {
		return report.Results{}, err
	}
	traceOut, _ = probes.Trace(target, 20, timeout)

	phase("mtu")
	step("→ MTU / Path MTU probe…")
	printer.Println("→ MTU / Path MTU probe…")
	log.Println("Running MTU / Path MTU probe")
	if err := checkCtx(); err != nil {
		return report.Results{}, err
	}
	mtu, _ = probes.MTUCheck(target)

	findings := make([]report.Finding, 0)
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

	classification, reasons := classify(netInfo, gwPing, wanPing, dnsLocal, mtu)

	res := report.Results{
		When:           time.Now(),
		NetInfo:        netInfo,
		Discovered:     l2Hosts,
		GwPing:         gwPing,
		WanPing:        wanPing,
		DNSLocal:       dnsLocal,
		DNSCF:          dnsCF,
		Trace:          traceOut,
		MTU:            mtu,
		Findings:       findings,
		GwLossPct:      fmt.Sprintf("%.0f%%", gwPing.Loss*100),
		WanLossPct:     fmt.Sprintf("%.0f%%", wanPing.Loss*100),
		TargetHost:     target,
		HasGateway:     gw != "",
		GatewayUsed:    gw,
		GwJitterMs:     gwPing.JitterMs,
		WanJitterMs:    wanPing.JitterMs,
		Classification: classification,
		Reasons:        reasons,
	}

	return res, nil
}

type classificationIssue struct {
	label    string
	reason   string
	severity int
}

func classify(netInfo probes.NetInfo, gwPing, wanPing probes.PingResult, dnsLocal probes.DNSResult, mtu probes.MTUResult) (string, []string) {
	const (
		gwLossThreshold    = 0.1
		gwJitterThreshold  = 20
		wanLossThreshold   = 0.05
		wanJitterThreshold = 30
		dnsSlowThreshold   = 150
		dnsCleanLossThresh = 0.02
		mtuMinHealthy      = 1500
	)

	hasGateway := netInfo.DefaultGateway != "" || len(netInfo.Gateways) > 0
	gatewayBad := hasGateway && (gwPing.Loss >= gwLossThreshold || gwPing.JitterMs >= gwJitterThreshold)
	wanBad := wanPing.Loss >= wanLossThreshold || wanPing.JitterMs >= wanJitterThreshold

	issues := make([]classificationIssue, 0)
	if gatewayBad {
		issues = append(issues, classificationIssue{
			label:    "LAN problem likely",
			reason:   fmt.Sprintf("Gateway ping unstable (loss %.1f%%, jitter %.1f ms)", gwPing.Loss*100, gwPing.JitterMs),
			severity: 3,
		})
	}
	if !gatewayBad && wanBad {
		issues = append(issues, classificationIssue{
			label:    "WAN/ISP issue likely",
			reason:   fmt.Sprintf("WAN target showing impairment (loss %.1f%%, jitter %.1f ms)", wanPing.Loss*100, wanPing.JitterMs),
			severity: 2,
		})
	}
	if !gatewayBad && !wanBad && dnsLocal.AvgMs >= dnsSlowThreshold && gwPing.Loss < dnsCleanLossThresh && wanPing.Loss < dnsCleanLossThresh {
		issues = append(issues, classificationIssue{
			label:    "DNS slow",
			reason:   fmt.Sprintf("System DNS lookups averaging %.0f ms", dnsLocal.AvgMs),
			severity: 1,
		})
	}
	vpnAdapters := netInfo.VPNAdapterNames()
	if mtu.PathMTU > 0 && mtu.PathMTU < mtuMinHealthy && len(vpnAdapters) > 0 {
		issues = append(issues, classificationIssue{
			label:    "MTU/MSS issue",
			reason:   fmt.Sprintf("Path MTU %d bytes with VPN/tunnel adapter(s) %s", mtu.PathMTU, strings.Join(vpnAdapters, ", ")),
			severity: 2,
		})
	}

	reasons := make([]string, len(issues))
	for i, issue := range issues {
		reasons[i] = issue.reason
	}

	classification := "Healthy"
	if len(issues) > 0 {
		classification = issues[0].label
		highest := issues[0].severity
		for _, issue := range issues[1:] {
			if issue.severity > highest {
				classification = issue.label
				highest = issue.severity
			}
		}
	}

	return classification, reasons
}
