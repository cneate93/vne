package probes

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type TraceResult struct {
	Raw string `json:"raw"`
}

func Trace(target string, maxHops int, timeout time.Duration) (TraceResult, error) {
	if maxHops <= 0 {
		maxHops = 30
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), target)
	default:
		if traceroutePath, err := exec.LookPath("traceroute"); err == nil {
			cmd = exec.CommandContext(ctx, traceroutePath, "-n", "-m", strconv.Itoa(maxHops), target)
		} else if tracepathPath, tracepathErr := exec.LookPath("tracepath"); tracepathErr == nil {
			// Fallback to tracepath if traceroute is unavailable.
			cmd = exec.CommandContext(ctx, tracepathPath, "-n", target)
		} else {
			msg := "neither traceroute nor tracepath command is available on this system; unable to run traceroute"
			return TraceResult{Raw: msg}, fmt.Errorf(msg)
		}
	}

	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && len(out) == 0 {
		out = []byte(fmt.Sprintf("traceroute timed out after %s", timeout))
	}
	result := TraceResult{Raw: string(out)}
	if err != nil {
		trimmed := strings.TrimSpace(result.Raw)
		if trimmed != "" {
			result.Raw = trimmed
		} else {
			switch runtime.GOOS {
			case "windows":
				switch {
				case errors.Is(err, exec.ErrNotFound):
					result.Raw = "tracert command not found on Windows; unable to run traceroute."
				default:
					var exitErr *exec.ExitError
					if errors.As(err, &exitErr) {
						result.Raw = fmt.Sprintf("tracert exited with code %d and produced no output.", exitErr.ExitCode())
					} else {
						result.Raw = fmt.Sprintf("failed to run tracert: %v", err)
					}
				}
			default:
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					result.Raw = fmt.Sprintf("trace command exited with code %d and produced no output.", exitErr.ExitCode())
				} else if errors.Is(err, exec.ErrNotFound) {
					result.Raw = "trace command not found; ensure traceroute or tracepath is installed."
				} else {
					result.Raw = fmt.Sprintf("failed to run trace command: %v", err)
				}
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
