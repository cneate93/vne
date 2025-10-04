package probes

import (
	"errors"
	"fmt"
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
	if err != nil && runtime.GOOS == "windows" {
		trimmed := strings.TrimSpace(result.Raw)
		switch {
		case errors.Is(err, exec.ErrNotFound):
			result.Raw = "tracert command not found on Windows; unable to run traceroute."
		case trimmed != "":
			result.Raw = trimmed
		default:
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				result.Raw = fmt.Sprintf("tracert exited with code %d and produced no output.", exitErr.ExitCode())
			} else {
				result.Raw = fmt.Sprintf("failed to run tracert: %v", err)
			}
		}
	}
	if err != nil {
		return result, err
	}
	// tracepath default limit may differ; annotate hops if necessary.
	if runtime.GOOS != "windows" && strings.Contains(cmd.Path, "tracepath") {
		result.Raw = strings.TrimSpace(result.Raw)
	}
	return result, nil
}
