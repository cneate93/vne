package probes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PingResult struct {
	AvgMs    float64 `json:"avg_ms"`
	P95Ms    float64 `json:"p95_ms"`
	JitterMs float64 `json:"jitter_ms"`
	Loss     float64 `json:"loss"`
	Raw      string  `json:"raw"`
}

func PingHost(target string, count int, timeout time.Duration) (PingResult, error) {
	if count <= 0 {
		count = 4
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", strconv.Itoa(count), target)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-n", target)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("ping timed out after %s", timeout)
		}
		// When ping exits with a non-zero status we still want to surface the raw output.
		// If no output was produced, fall back to stderr for context.
		if len(output) == 0 {
			output = stderr.Bytes()
		}
		if output == nil {
			output = []byte{}
		}
	}

	res := parsePing(string(output))
	if err != nil {
		return res, errors.New(strings.TrimSpace(err.Error() + " " + stderr.String()))
	}
	return res, nil
}

var lossRe = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)%\s*loss`)
var percentRe = regexp.MustCompile(`(\d+(?:\.\d+)?)%`)

var pingTimeRe = regexp.MustCompile(`(?i)time[=<]?\s*([0-9]+(?:\.[0-9]+)?)\s*ms`)

func parsePing(out string) PingResult {
	result := PingResult{Raw: out}
	lines := strings.Split(out, "\n")
	parsedLoss := false
	samples := extractPingSamples(out)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if !parsedLoss {
			if m := lossRe.FindStringSubmatch(lower); len(m) == 2 {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					result.Loss = v / 100
					parsedLoss = true
				}
			} else if m := percentRe.FindStringSubmatch(lower); len(m) == 2 && strings.Contains(lower, "loss") {
				if v, err := strconv.ParseFloat(m[1], 64); err == nil {
					result.Loss = v / 100
					parsedLoss = true
				}
			}
		}

		switch {
		case strings.Contains(lower, "min/avg"), strings.Contains(lower, "min ="):
			result.AvgMs = extractAvg(trimmed)
		case strings.HasPrefix(lower, "average ="):
			if avg, err := parseNumberBetween(trimmed, "=", "ms"); err == nil {
				result.AvgMs = avg
			}
		case strings.Contains(lower, "round-trip"):
			result.AvgMs = extractAvg(trimmed)
		}
	}

	if result.AvgMs == 0 && len(samples) > 0 {
		result.AvgMs = average(samples)
	}
	result.P95Ms = percentile95(samples)
	result.JitterMs = jitter(samples)

	return result
}

func extractAvg(line string) float64 {
	parts := strings.Split(line, "=")
	if len(parts) < 2 {
		return 0
	}
	stats := strings.TrimSpace(parts[len(parts)-1])
	stats = strings.TrimSuffix(stats, " ms")
	stats = strings.TrimSuffix(stats, " milliseconds")
	pieces := strings.Split(stats, "/")
	if len(pieces) >= 2 {
		if avg, err := strconv.ParseFloat(strings.TrimSpace(pieces[1]), 64); err == nil {
			return avg
		}
	}
	return 0
}

func parseNumberBetween(line, left, right string) (float64, error) {
	start := strings.Index(line, left)
	if start == -1 {
		return 0, errors.New("left marker not found")
	}
	start += len(left)
	end := len(line)
	if right != "" {
		if idx := strings.Index(line[start:], right); idx != -1 {
			end = start + idx
		}
	}
	segment := strings.TrimSpace(line[start:end])
	segment = strings.TrimSuffix(segment, "ms")
	segment = strings.TrimSpace(segment)
	segment = strings.TrimSuffix(segment, "ms")
	segment = strings.TrimSpace(segment)
	if strings.HasSuffix(segment, "ms") {
		segment = strings.TrimSpace(segment[:len(segment)-2])
	}
	return strconv.ParseFloat(segment, 64)
}

func extractPingSamples(raw string) []float64 {
	matches := pingTimeRe.FindAllStringSubmatch(raw, -1)
	if len(matches) == 0 {
		return nil
	}
	samples := make([]float64, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		samples = append(samples, v)
	}
	return samples
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func percentile95(values []float64) float64 {
	n := len(values)
	if n == 0 {
		return 0
	}
	sorted := make([]float64, n)
	copy(sorted, values)
	sort.Float64s(sorted)
	idx := int(math.Ceil(0.95*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

func jitter(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	deltas := make([]float64, 0, len(values)-1)
	prev := values[0]
	for _, sample := range values[1:] {
		deltas = append(deltas, sample-prev)
		prev = sample
	}
	if len(deltas) == 0 {
		return 0
	}
	var sum float64
	for _, d := range deltas {
		sum += d
	}
	mean := sum / float64(len(deltas))
	var variance float64
	for _, d := range deltas {
		diff := d - mean
		variance += diff * diff
	}
	variance /= float64(len(deltas))
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}
