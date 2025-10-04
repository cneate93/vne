package packs

import (
	"strings"

	"github.com/cneate93/vne/internal/probes"
)

type packCandidate struct {
	key      string
	matchers []string
}

var candidates = []packCandidate{
	{key: "fortigate", matchers: []string{"fortinet"}},
	{key: "cisco_ios", matchers: []string{"cisco"}},
}

// PacksFor returns the vendor-specific packs that should be suggested based on
// the provided layer-2 discovery results.
func PacksFor(discovered []probes.L2Host) []string {
	seen := make(map[string]struct{})
	var packs []string
	for _, host := range discovered {
		vendor := strings.ToLower(strings.TrimSpace(host.Vendor))
		if vendor == "" {
			continue
		}
		for _, cand := range candidates {
			if _, ok := seen[cand.key]; ok {
				continue
			}
			if matchesVendor(vendor, cand.matchers) {
				seen[cand.key] = struct{}{}
				packs = append(packs, cand.key)
			}
		}
	}
	return packs
}

func matchesVendor(vendor string, matchers []string) bool {
	for _, m := range matchers {
		if m == "" {
			continue
		}
		if strings.Contains(vendor, m) {
			return true
		}
	}
	return false
}
