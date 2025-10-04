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

	baseCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	deadline, hasDeadline := baseCtx.Deadline()

	var total float64
	var count int
	answers := make([]string, 0)

	for _, resolver := range resolvers {
		remaining := timeout
		if hasDeadline {
			remaining = time.Until(deadline)
			if remaining <= 0 {
				break
			}
		}

		lookupCtx, lookupCancel := context.WithTimeout(baseCtx, remaining)

		r := net.Resolver{}
		resolverAddr := resolver
		if resolverAddr != "" {
			r = net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					timeoutForDial := remaining
					if hasDeadline {
						if until := time.Until(deadline); until < timeoutForDial {
							timeoutForDial = until
						}
						if timeoutForDial <= 0 {
							return nil, context.DeadlineExceeded
						}
					}

					d := &net.Dialer{Timeout: timeoutForDial}
					return d.DialContext(ctx, network, net.JoinHostPort(resolverAddr, "53"))
				},
			}
		}

		start := time.Now()
		ips, err := r.LookupHost(lookupCtx, host)
		elapsed := time.Since(start).Seconds() * 1000
		lookupCancel()
		if err == nil {
			total += elapsed
			count++
			answers = append(answers, ips...)
		}

		if hasDeadline && time.Until(deadline) <= 0 {
			break
		}
	}

	var avg float64
	if count > 0 {
		avg = total / float64(count)
	}

	return DNSResult{AvgMs: avg, Answers: answers}, nil
}
