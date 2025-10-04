package report

import (
	"bytes"
	"html/template"
	"os"
	"time"

	"vne/internal/probes"
)

type Finding struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Results struct {
	When        time.Time          `json:"when"`
	UserNote    string             `json:"user_note"`
	NetInfo     probes.NetInfo     `json:"net_info"`
	GwPing      probes.PingResult  `json:"gw_ping"`
	WanPing     probes.PingResult  `json:"wan_ping"`
	DNSLocal    probes.DNSResult   `json:"dns_local"`
	DNSCF       probes.DNSResult   `json:"dns_cf"`
	Trace       probes.TraceResult `json:"trace"`
	MTU         probes.MTUResult   `json:"mtu"`
	Findings    []Finding          `json:"findings"`
	FortiRaw    any                `json:"forti_raw,omitempty"`
	GwLossPct   string             `json:"gw_loss_pct"`
	WanLossPct  string             `json:"wan_loss_pct"`
	TargetHost  string             `json:"target_host"`
	HasGateway  bool               `json:"has_gateway"`
	GatewayUsed string             `json:"gateway_used"`
}

func RenderHTML(r Results, tmplPath, outPath string) error {
	tplBytes, err := os.ReadFile(tmplPath)
	if err != nil {
		return err
	}
	tpl, err := template.New("rep").Parse(string(tplBytes))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, r); err != nil {
		return err
	}
	return os.WriteFile(outPath, buf.Bytes(), 0644)
}
