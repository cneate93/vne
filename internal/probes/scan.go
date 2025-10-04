package probes

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type L2Host struct {
	IfName string `json:"if_name"`
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
}

type scanTarget struct {
	IfName  string
	LocalIP net.IP
	Network *net.IPNet
	Hosts   []string
}

// L2Scan performs a best-effort layer-2 discovery by ping sweeping the local
// subnets for each active interface with a private IPv4 address (up to
// maxHosts hosts per interface) and then parsing the system ARP cache. It
// returns the discovered hosts in the ARP table.
func L2Scan(timeout time.Duration, maxHosts int) ([]L2Host, error) {
	if maxHosts <= 0 {
		maxHosts = 256
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	pingPath, err := exec.LookPath("ping")
	if err != nil {
		return []L2Host{}, fmt.Errorf("ping command not found: %w", err)
	}
	arpPath, err := exec.LookPath("arp")
	if err != nil {
		return []L2Host{}, fmt.Errorf("arp command not found: %w", err)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return []L2Host{}, fmt.Errorf("list interfaces: %w", err)
	}

	var targets []*scanTarget
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || !ip4.IsPrivate() {
				continue
			}
			sweepNet := adjustSweepNetwork(ip4, ipNet)
			if sweepNet == nil {
				continue
			}
			hosts := enumerateHosts(ip4, sweepNet, maxHosts)
			if len(hosts) == 0 {
				continue
			}
			targets = append(targets, &scanTarget{
				IfName:  iface.Name,
				LocalIP: append(net.IP(nil), ip4...),
				Network: sweepNet,
				Hosts:   hosts,
			})
		}
	}

	if len(targets) == 0 {
		return []L2Host{}, nil
	}

	hostSet := map[string]struct{}{}
	var toPing []string
	for _, t := range targets {
		for _, ip := range t.Hosts {
			if ip == t.LocalIP.String() {
				continue
			}
			if _, ok := hostSet[ip]; ok {
				continue
			}
			hostSet[ip] = struct{}{}
			toPing = append(toPing, ip)
		}
	}

	if len(toPing) > 0 {
		concurrency := 32
		if len(toPing) < concurrency {
			concurrency = len(toPing)
		}
		if concurrency < 1 {
			concurrency = 1
		}
		var wg sync.WaitGroup
		jobs := make(chan string)
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range jobs {
					_ = runPing(pingPath, ip, timeout)
				}
			}()
		}
		for _, ip := range toPing {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
	}

	arpOut, err := exec.Command(arpPath, "-a").CombinedOutput()
	if err != nil {
		return []L2Host{}, fmt.Errorf("execute arp -a: %w", err)
	}

	hosts := parseARP(string(arpOut), targets)
	return hosts, nil
}

func runPing(pingPath, ip string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	args := pingArgs(ip, timeout)
	cmd := exec.CommandContext(ctx, pingPath, args...)
	return cmd.Run()
}

func pingArgs(ip string, timeout time.Duration) []string {
	if runtime.GOOS == "windows" {
		ms := int(timeout / time.Millisecond)
		if ms < 1000 {
			ms = 1000
		}
		return []string{"-n", "1", "-w", strconv.Itoa(ms), ip}
	}
	sec := int(timeout / time.Second)
	if sec < 1 {
		sec = 1
	}
	return []string{"-c", "1", "-W", strconv.Itoa(sec), ip}
}

func adjustSweepNetwork(ip net.IP, ipNet *net.IPNet) *net.IPNet {
	if ipNet == nil {
		return nil
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 0 {
		return nil
	}
	target := ones
	if target < 24 {
		target = 24
	}
	if ones > 24 {
		target = ones
	}
	if target > 32 {
		target = 32
	}
	mask := net.CIDRMask(target, 32)
	networkIP := ip.Mask(mask)
	return &net.IPNet{IP: networkIP, Mask: mask}
}

func enumerateHosts(localIP net.IP, network *net.IPNet, limit int) []string {
	if network == nil {
		return nil
	}
	base := network.IP.Mask(network.Mask).To4()
	if base == nil {
		return nil
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 0 || ones > 32 {
		return nil
	}
	total := 1 << (bits - ones)
	if total <= 0 {
		return nil
	}
	maxCount := total
	if limit > 0 && limit < maxCount {
		maxCount = limit
	}
	skipEdges := ones <= 30
	var hosts []string
	for i := 0; i < total && len(hosts) < maxCount; i++ {
		if skipEdges && (i == 0 || i == total-1) {
			continue
		}
		ip := incIP(base, uint32(i))
		hosts = append(hosts, ip.String())
	}
	if len(hosts) == 0 && total > 0 {
		// fall back to including the interface IP if subnet is /31 or /32
		hosts = append(hosts, localIP.String())
	}
	return hosts
}

func incIP(base net.IP, inc uint32) net.IP {
	v := binary.BigEndian.Uint32(base)
	v += inc
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return net.IP(buf[:])
}

func parseARP(output string, targets []*scanTarget) []L2Host {
	if len(output) == 0 {
		return nil
	}
	byIface := map[string][]*scanTarget{}
	byLocalIP := map[string][]*scanTarget{}
	for _, t := range targets {
		name := strings.ToLower(t.IfName)
		byIface[name] = append(byIface[name], t)
		byLocalIP[t.LocalIP.String()] = append(byLocalIP[t.LocalIP.String()], t)
	}

	lines := strings.Split(output, "\n")
	var current []*scanTarget
	seen := map[string]struct{}{}
	var hosts []L2Host

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Interface:") {
			current = nil
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			rest := strings.TrimSpace(parts[1])
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			if targetsForIP, ok := byLocalIP[fields[0]]; ok {
				current = targetsForIP
			}
			continue
		}

		if idx := strings.Index(line, " at "); idx != -1 && strings.Contains(line, " on ") {
			// Unix-like format: "? (ip) at mac on iface ..."
			ip := extractBetween(line, "(", ")")
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				continue
			}
			remainder := line[idx+4:]
			onRelIdx := strings.Index(remainder, " on ")
			if onRelIdx == -1 {
				continue
			}
			macPart := strings.TrimSpace(remainder[:onRelIdx])
			mac := normalizeMAC(macPart)
			if mac == "" {
				continue
			}
			onIdx := strings.Index(line, " on ")
			if onIdx == -1 {
				continue
			}
			afterOn := line[onIdx+4:]
			ifaceField := strings.Fields(afterOn)
			if len(ifaceField) == 0 {
				continue
			}
			ifaceName := strings.TrimSpace(ifaceField[0])
			var candidates []*scanTarget
			if t, ok := byIface[strings.ToLower(ifaceName)]; ok {
				candidates = append(candidates, t...)
			}
			// fallback: any interface whose network contains the IP
			if len(candidates) == 0 {
				for _, t := range targets {
					candidates = append(candidates, t)
				}
			}
			addHost(&hosts, seen, candidates, parsedIP, ifaceName, mac)
			continue
		}

		// Windows table entry
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hostIP := net.ParseIP(fields[0])
		if hostIP == nil {
			continue
		}
		mac := normalizeMAC(fields[1])
		if mac == "" {
			continue
		}
		if len(current) == 0 {
			continue
		}
		addHost(&hosts, seen, current, hostIP, "", mac)
	}
	return hosts
}

func addHost(hosts *[]L2Host, seen map[string]struct{}, candidates []*scanTarget, ip net.IP, ifaceHint, mac string) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, cand := range candidates {
		if cand == nil || !cand.Network.Contains(ip) {
			continue
		}
		if ifaceHint != "" && !strings.EqualFold(cand.IfName, ifaceHint) {
			// If we have an interface hint, prefer matching it.
			continue
		}
		key := cand.IfName + "|" + ip.String() + "|" + mac
		if _, exists := seen[key]; exists {
			return true
		}
		seen[key] = struct{}{}
		*hosts = append(*hosts, L2Host{IfName: cand.IfName, IP: ip.String(), MAC: mac})
		return true
	}
	// no strict match; try again without interface hint requirement
	for _, cand := range candidates {
		if cand == nil || !cand.Network.Contains(ip) {
			continue
		}
		key := cand.IfName + "|" + ip.String() + "|" + mac
		if _, exists := seen[key]; exists {
			return true
		}
		seen[key] = struct{}{}
		*hosts = append(*hosts, L2Host{IfName: cand.IfName, IP: ip.String(), MAC: mac})
		return true
	}
	return false
}

func normalizeMAC(raw string) string {
	mac := strings.TrimSpace(strings.ToLower(raw))
	if mac == "" || strings.Contains(mac, "incomplete") {
		return ""
	}
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, ".", "")
	mac = strings.Trim(mac, "()")
	if strings.Count(mac, ":") == 0 && len(mac) == 12 {
		var parts []string
		for i := 0; i < 12; i += 2 {
			parts = append(parts, mac[i:i+2])
		}
		mac = strings.Join(parts, ":")
	}
	if !strings.Contains(mac, ":") {
		return ""
	}
	if strings.Contains(mac, "ff:ff:ff:ff:ff:ff") || strings.Contains(mac, "00:00:00:00:00:00") {
		return ""
	}
	return mac
}

func extractBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i == -1 {
		return ""
	}
	j := strings.Index(s[i+len(start):], end)
	if j == -1 {
		return ""
	}
	return s[i+len(start) : i+len(start)+j]
}
