package probes

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type TraceResult struct {
	Raw string `json:"raw"`
}

func Trace(target string, maxHops int) (TraceResult, error) {
	if maxHops <= 0 {
		maxHops = 30
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tracert", "-d", "-h", strconv.Itoa(maxHops), target)
	default:
		if _, err := exec.LookPath("traceroute"); err == nil {
			cmd = exec.Command("traceroute", "-n", "-m", strconv.Itoa(maxHops), target)
		} else {
			// Fallback to tracepath if traceroute is unavailable.
			cmd = exec.Command("tracepath", "-n", target)
		}
	}

	out, err := cmd.CombinedOutput()
	result := TraceResult{Raw: string(out)}
	if err != nil {
		return result, err
	}
	// tracepath default limit may differ; annotate hops if necessary.
	if runtime.GOOS != "windows" && strings.Contains(cmd.Path, "tracepath") {
		result.Raw = strings.TrimSpace(result.Raw)
	}
	return result, nil
}
