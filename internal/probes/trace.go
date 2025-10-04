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

	var (
		cmd         *exec.Cmd
		commandName string
	)

	switch runtime.GOOS {
	case "windows":
		if _, err := exec.LookPath("tracert"); err != nil {
			msg := "tracert command not found on Windows; install the tracert utility to enable traceroute."
			return TraceResult{Raw: msg}, fmt.Errorf("tracert lookup failed: %w", err)
		}
		commandName = "tracert"
		cmd = exec.CommandContext(ctx, commandName, "-d", "-h", strconv.Itoa(maxHops), target)
	case "linux":
		traceroutePath, tracerouteErr := exec.LookPath("traceroute")
		if tracerouteErr == nil {
			commandName = "traceroute"
			cmd = exec.CommandContext(ctx, traceroutePath, "-n", "-m", strconv.Itoa(maxHops), target)
		} else {
			tracepathPath, tracepathErr := exec.LookPath("tracepath")
			if tracepathErr == nil {
				commandName = "tracepath"
				cmd = exec.CommandContext(ctx, tracepathPath, "-n", target)
			} else {
				msg := "Neither traceroute nor tracepath commands were found on this Linux system. Install traceroute (or tracepath) to enable network path tracing."
				return TraceResult{Raw: msg}, fmt.Errorf("no traceroute utility found: traceroute: %w, tracepath: %w", tracerouteErr, tracepathErr)
			}
		}
	default:
		if _, err := exec.LookPath("traceroute"); err != nil {
			msg := "traceroute command not found; install traceroute to enable network path tracing."
			return TraceResult{Raw: msg}, fmt.Errorf("traceroute lookup failed: %w", err)
		}
		commandName = "traceroute"
		cmd = exec.CommandContext(ctx, commandName, "-n", "-m", strconv.Itoa(maxHops), target)
	}

	out, err := cmd.CombinedOutput()
	raw := strings.TrimSpace(string(out))
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && raw == "" {
		raw = fmt.Sprintf("traceroute timed out after %s", timeout)
	}

	if err != nil {
		if raw == "" {
			switch {
			case runtime.GOOS == "windows" && errors.Is(err, exec.ErrNotFound):
				raw = "tracert command not found on Windows; unable to run traceroute."
			case errors.Is(err, exec.ErrNotFound):
				raw = fmt.Sprintf("%s command not found; ensure it is installed and available in PATH.", commandName)
			default:
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					raw = fmt.Sprintf("%s exited with code %d and produced no output.", commandName, exitErr.ExitCode())
				} else {
					raw = fmt.Sprintf("failed to run %s: %v", commandName, err)
				}
			}
		}
		return TraceResult{Raw: raw}, err
	}

	if raw == "" {
		if commandName == "" {
			commandName = "traceroute"
		}
		raw = fmt.Sprintf("%s completed without producing output.", commandName)
	}

	return TraceResult{Raw: raw}, nil
}
