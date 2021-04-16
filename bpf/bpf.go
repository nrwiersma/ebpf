package bpf

import _ "embed"

//go:embed dist/metrics_sock.o
var MetricsSock []byte
