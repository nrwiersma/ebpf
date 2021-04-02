package ebpf

import (
	"encoding/binary"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/OneOfOne/xxhash"
	"github.com/hamba/timex"
	"github.com/influxdata/tdigest"
)

type record struct {
	Subject  string
	Remote   string
	Port     uint16
	Protocol string
	BytesIn  uint64
	BytesOut uint64
	RTT      float64
}

type metric struct {
	Timestamp int64
	Subject   string
	Remote    string
	Port      uint16
	Protocol  string
	BytesIn   uint64
	BytesOut  uint64
	RTT       *tdigest.TDigest
}

type metricService struct {
	active *[]record
	proc   []record

	hasher *xxhash.XXHash64
	fn     func(m []metric)

	doneCh chan struct{}
}

func newMetricsService(inter time.Duration, fn func([]metric)) *metricService {
	active := make([]record, 0, 512)

	svc := &metricService{
		active: &active,
		proc:   make([]record, 0, 512),
		hasher: xxhash.New64(),
		fn:     fn,
		doneCh: make(chan struct{}),
	}

	go svc.runProcess(inter)

	return svc
}

func (s *metricService) runProcess(inter time.Duration) {
	t := time.NewTicker(inter)
	defer t.Stop()

	for {
		select {
		case <-s.doneCh:
			return
		case <-t.C:
		}

		ptr := (*unsafe.Pointer)(unsafe.Pointer(&s.active))
		old := atomic.SwapPointer(ptr, unsafe.Pointer(&s.proc))
		s.proc = *(*[]record)(old)

		// TODO: Try reuse memory here.
		agg := map[uint64]metric{}
		for _, r := range s.proc {
			h := s.getHash(r)
			m, ok := agg[h]
			if !ok {
				m = metric{
					Subject:  r.Subject,
					Remote:   r.Remote,
					Port:     r.Port,
					Protocol: r.Protocol,
					RTT:      tdigest.New(),
				}
			}

			m.BytesOut += r.BytesOut
			m.BytesIn += r.BytesIn
			if r.RTT > 0 {
				m.RTT.Add(r.RTT, 1)
			}
			agg[h] = m
		}

		s.proc = s.proc[:0]

		ts := timex.Unix()
		ms := make([]metric, 0, len(agg))
		for _, m := range agg {
			m.Timestamp = ts
			ms = append(ms, m)
		}
		s.fn(ms)
	}
}

func (s *metricService) getHash(r record) uint64 {
	s.hasher.Reset()
	_, _ = s.hasher.WriteString(r.Subject)
	_, _ = s.hasher.WriteString(r.Remote)
	var pb [4]byte
	binary.BigEndian.PutUint16(pb[:], r.Port)
	_, _ = s.hasher.Write(pb[:])

	return s.hasher.Sum64()
}

// Add adds a record to be processed.
// This is not thread-safe.
func (s *metricService) Add(r record) {
	*s.active = append(*s.active, r)
}

// Close closes the metrics service
func (s *metricService) Close() error {
	close(s.doneCh)

	return nil
}
