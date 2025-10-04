package probes

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type MTUResult struct {
	PathMTU int    `json:"path_mtu"`
	Raw     string `json:"raw"`
}

func MTUCheck(target string) (MTUResult, error) {
	if runtime.GOOS == "windows" {
		sizes := []int{1472, 1460, 1452, 1400, 1300, 1200}
		for _, sz := range sizes {
			out, _ := exec.Command("ping", "-f", "-l", strconv.Itoa(sz), "-n", "2", target).CombinedOutput()
			txt := strings.ToLower(string(out))
			if !(strings.Contains(txt, "needs to be fragmented") || strings.Contains(txt, "packet needs to be fragmented")) {
				return MTUResult{PathMTU: sz + 28, Raw: string(out)}, nil
			}
		}
		return MTUResult{PathMTU: 0, Raw: "DF tests failed"}, nil
	}

	if runtime.GOOS == "linux" {
		sizes := []int{1472, 1460, 1452, 1400, 1300, 1200}
		for _, sz := range sizes {
			out, _ := exec.Command("ping", "-M", "do", "-s", strconv.Itoa(sz), "-c", "2", target).CombinedOutput()
			txt := strings.ToLower(string(out))
			if !(strings.Contains(txt, "message too long") || strings.Contains(txt, "frag needed")) {
				return MTUResult{PathMTU: sz + 28, Raw: string(out)}, nil
			}
		}
		return MTUResult{PathMTU: 0, Raw: "DF tests failed"}, nil
	}

	out, _ := exec.Command("ping", "-c", "2", target).CombinedOutput()
	return MTUResult{PathMTU: 0, Raw: string(out)}, nil
}
