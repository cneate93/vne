package probes

import (
	"encoding/json"
	"strings"

	"github.com/cneate93/vne/assets"
)

// VendorInfo describes the vendor associated with a MAC address prefix.
type VendorInfo struct {
	OUI  string
	Name string
}

var ouiVendors map[string]string

func init() {
	ouiVendors = map[string]string{}
	if len(assets.OUIData) == 0 {
		return
	}
	var raw map[string]string
	if err := json.Unmarshal(assets.OUIData, &raw); err != nil {
		return
	}
	for k, v := range raw {
		key := strings.ToLower(strings.TrimSpace(k))
		key = strings.ReplaceAll(key, "-", "")
		key = strings.ReplaceAll(key, ":", "")
		key = strings.ReplaceAll(key, ".", "")
		if len(key) != 6 {
			continue
		}
		ouiVendors[key] = strings.TrimSpace(v)
	}
}

// VendorFromMAC returns the vendor information associated with the provided MAC address.
func VendorFromMAC(mac string) (VendorInfo, bool) {
	cleaned := strings.ToLower(strings.TrimSpace(mac))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.ReplaceAll(cleaned, ".", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	if len(cleaned) < 6 {
		return VendorInfo{}, false
	}
	oui := cleaned[:6]
	name, ok := ouiVendors[oui]
	if !ok || name == "" {
		return VendorInfo{}, false
	}
	return VendorInfo{OUI: oui, Name: name}, true
}
