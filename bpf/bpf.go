package bpf

// Required for embed.
import _ "embed"

// MetricsSock is the eBPF metrics socket program.
//go:embed dist/metrics_sock.o
var MetricsSock []byte
