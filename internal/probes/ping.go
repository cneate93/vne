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

func DNSLookupTimed(host string, resolvers []string) (DNSResult, error) {
	if len(resolvers) == 0 {
		resolvers = []string{""}
	}
	var total float64
	var answers []string
	var n int
	for _, r := range resolvers {
		res := net.Resolver{}
		if r != "" {
			dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort(r, "53"))
			}
			res = net.Resolver{PreferGo: true, Dial: dialer}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		t0 := time.Now()
		ips, err := res.LookupHost(ctx, host)
		el := time.Since(t0).Seconds() * 1000.0
		cancel()
		if err == nil {
			total += el
			n++
			answers = append(answers, ips...)
		}
	}
	var avg float64
	if n > 0 {
		avg = total / float64(n)
	}
	return DNSResult{AvgMs: avg, Answers: answers}, nil
}
