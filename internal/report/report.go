package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/cneate93/vne/internal/probes"
	"github.com/cneate93/vne/internal/snmp"
)

//go:embed report_template.html
var defaultReportTemplate string

type Finding struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type CiscoInterface struct {
	Iface        string `json:"iface"`
	Duplex       string `json:"duplex"`
	Speed        string `json:"speed"`
	CRC          int    `json:"crc"`
	InputErrors  int    `json:"input_errs"`
	OutputErrors int    `json:"output_errs"`
}

type CiscoPackResults struct {
	Interfaces []CiscoInterface `json:"interfaces"`
	Findings   []Finding        `json:"findings"`
	Raw        string           `json:"raw"`
}

type Results struct {
	When              time.Time             `json:"when"`
	UserNote          string                `json:"user_note"`
	NetInfo           probes.NetInfo        `json:"net_info"`
	Discovered        []probes.L2Host       `json:"discovered,omitempty"`
	GwPing            probes.PingResult     `json:"gw_ping"`
	WanPing           probes.PingResult     `json:"wan_ping"`
	DNSLocal          probes.DNSResult      `json:"dns_local"`
	DNSCF             probes.DNSResult      `json:"dns_cf"`
	Trace             probes.TraceResult    `json:"trace"`
	MTU               probes.MTUResult      `json:"mtu"`
	Findings          []Finding             `json:"findings"`
	FortiRaw          any                   `json:"forti_raw,omitempty"`
	CiscoIOS          *CiscoPackResults     `json:"cisco_ios,omitempty"`
	IfaceHealth       *snmp.InterfaceHealth `json:"iface_health,omitempty"`
	GwLossPct         string                `json:"gw_loss_pct"`
	WanLossPct        string                `json:"wan_loss_pct"`
	TargetHost        string                `json:"target_host"`
	HasGateway        bool                  `json:"has_gateway"`
	GatewayUsed       string                `json:"gateway_used"`
	GwJitterMs        float64               `json:"gw_jitter_ms"`
	WanJitterMs       float64               `json:"wan_jitter_ms"`
	Classification    string                `json:"classification"`
	Reasons           []string              `json:"reasons"`
	VendorSuggestions []string              `json:"vendor_suggestions,omitempty"`
	VendorSummaries   []Finding             `json:"vendor_summaries,omitempty"`
	VendorFindings    []Finding             `json:"vendor_findings,omitempty"`
}

func RenderHTML(r Results, tmplPath, outPath string) error {
	tplBytes, err := os.ReadFile(tmplPath)
	if err != nil {
		tplBytes = []byte(defaultReportTemplate)
	}
	funcMap := template.FuncMap{
		"pct": func(v float64) string {
			return fmt.Sprintf("%.0f%%", v*100)
		},
		"ms1": func(v float64) string {
			return fmt.Sprintf("%.1f ms", v)
		},
		"humanSpeed": humanSpeed,
	}
	tpl, err := template.New("rep").Funcs(funcMap).Parse(string(tplBytes))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, r); err != nil {
		return err
	}
	return os.WriteFile(outPath, buf.Bytes(), 0644)
}

func humanSpeed(bps uint64) string {
	if bps == 0 {
		return "0 bps"
	}
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	value := float64(bps)
	unitIdx := 0
	for value >= 1000 && unitIdx < len(units)-1 {
		value /= 1000
		unitIdx++
	}
	if value >= 10 || unitIdx == 0 {
		return fmt.Sprintf("%.0f %s", value, units[unitIdx])
	}
	return fmt.Sprintf("%.1f %s", value, units[unitIdx])
}
