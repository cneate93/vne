package probes

import (
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type NetInfo struct {
	HostName       string   `json:"hostname"`
	Interfaces     []IF     `json:"interfaces"`
	Gateways       []string `json:"gateways"`
	DefaultGateway string   `json:"default_gateway"`
	DNSServers     []string `json:"dns_servers"`
}

type IF struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
	Mac  string   `json:"mac"`
	Up   bool     `json:"up"`
}

// VPNAdapterNames returns the set of active interfaces that appear to be
// VPN/tunnel adapters. This is based on common interface name patterns for
// popular VPN clients and tunnelling drivers (WireGuard, OpenVPN, etc.).
var vpnAdapterRegex = regexp.MustCompile(`(?i)(nord|openvpn|wireguard|^tun|^tap|^wg)`)

func (ni NetInfo) VPNAdapterNames() []string {
	var matches []string
	for _, iface := range ni.Interfaces {
		if !iface.Up {
			continue
		}
		if vpnAdapterRegex.MatchString(strings.TrimSpace(iface.Name)) {
			matches = append(matches, iface.Name)
		}
	}
	return matches
}

func GetBasics() (NetInfo, error) {
	var ni NetInfo
	hn, _ := execLook("hostname")
	ni.HostName = hn

	ifs, _ := net.Interfaces()
	for _, it := range ifs {
		addrs, _ := it.Addrs()
		var ips []string
		for _, a := range addrs {
			ips = append(ips, a.String())
		}
		ni.Interfaces = append(ni.Interfaces, IF{
			Name: it.Name, IPs: ips, Mac: it.HardwareAddr.String(),
			Up: it.Flags&net.FlagUp != 0,
		})
	}

	ni.DNSServers = readResolvConf()

	gws := guessGateways()
	ni.Gateways = gws
	if len(gws) > 0 {
		ni.DefaultGateway = gws[0]
	}
	return ni, nil
}

func readResolvConf() []string {
	if runtime.GOOS == "windows" {
		out, _ := exec.Command("ipconfig", "/all").CombinedOutput()
		lines := strings.Split(string(out), "\n")
		var dns []string
		capturing := false
		for _, l := range lines {
			ll := strings.TrimSpace(l)
			lc := strings.ToLower(ll)
			if strings.HasPrefix(lc, "dns servers") {
				capturing = true
				parts := strings.Split(ll, ":")
				if len(parts) > 1 {
					d := strings.TrimSpace(parts[1])
					if d != "" {
						dns = append(dns, d)
					}
				}
				continue
			}
			if capturing {
				// subsequent lines often list more servers until a blank or new section
				if ll == "" || strings.Contains(ll, ":") {
					capturing = false
					continue
				}
				if strings.Count(ll, ".") >= 1 {
					dns = append(dns, ll)
				}
			}
		}
		return dns
	}
	// Unix-like: parse /etc/resolv.conf via cat (portable)
	b, err := exec.Command("cat", "/etc/resolv.conf").CombinedOutput()
	if err != nil {
		return nil
	}
	var dns []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "nameserver") {
			fields := strings.Fields(l)
			if len(fields) >= 2 {
				dns = append(dns, fields[1])
			}
		}
	}
	return dns
}

func guessGateways() []string {
	if runtime.GOOS == "windows" {
		out, _ := exec.Command("route", "print", "0.0.0.0").CombinedOutput()
		// Best-effort parse: look for lines like "0.0.0.0 ... <gateway> ..."
		var gws []string
		for _, l := range strings.Split(string(out), "\n") {
			ll := strings.Fields(strings.TrimSpace(l))
			if len(ll) >= 4 && ll[0] == "0.0.0.0" && ll[1] == "0.0.0.0" {
				gws = append(gws, ll[2])
			}
		}
		return gws
	}
	out, _ := exec.Command("ip", "route").CombinedOutput()
	if len(out) == 0 {
		out, _ = exec.Command("route", "-n").CombinedOutput()
	}
	var gws []string
	for _, l := range strings.Split(string(out), "\n") {
		ll := strings.TrimSpace(l)
		if strings.HasPrefix(ll, "default via") {
			parts := strings.Fields(ll) // default via X dev Y
			if len(parts) >= 3 {
				gws = append(gws, parts[2])
			}
		}
	}
	return gws
}

func execLook(cmd string) (string, error) {
	b, err := exec.Command(cmd).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}
