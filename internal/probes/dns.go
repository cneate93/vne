package probes

import (
	"context"
	"net"
	"time"
)

type DNSResult struct {
	AvgMs   float64  `json:"avg_ms"`
	Answers []string `json:"answers"`
}

func DNSLookupTimed(host string, resolvers []string, timeout time.Duration) (DNSResult, error) {
	if len(resolvers) == 0 {
		resolvers = []string{""}
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var total float64
	var count int
	answers := make([]string, 0)

	for _, resolver := range resolvers {
		r := net.Resolver{}
		if resolver != "" {
			dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
				d := &net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, net.JoinHostPort(resolver, "53"))
			}
			r = net.Resolver{PreferGo: true, Dial: dialer}
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		start := time.Now()
		ips, err := r.LookupHost(ctx, host)
		elapsed := time.Since(start).Seconds() * 1000
		cancel()
		if err == nil {
			total += elapsed
			count++
			answers = append(answers, ips...)
		}
	}

	var avg float64
	if count > 0 {
		avg = total / float64(count)
	}

	return DNSResult{AvgMs: avg, Answers: answers}, nil
}
