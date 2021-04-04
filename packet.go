package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/hashicorp/go-multierror"
)

//go:embed bpf/dist/metrics.o
var bpf []byte

// Packet flags.
const (
	flagIn = 1 << iota
	flagOut
)

// Packet protocols.
const (
	protoUDP = iota + 1
	protoTCP
)

// packet contains network packet data.
//
// Must stay in sync with bpf/metrics.h pkt_entry.
type packet struct {
	Timestamp uint64
	SrcIP     [16]byte
	DestIP    [16]byte
	SrcPort   uint16
	DestPort  uint16
	Len       uint32
	RTT       uint32
	Proto     uint16
	Flags     uint16
}

func toPacket(raw []byte) packet {
	return *(*packet)(unsafe.Pointer(&raw[0]))
}

type objects struct {
	Ingress *ebpf.Program `ebpf:"metrics_ingress"`
	Egress  *ebpf.Program `ebpf:"metrics_egress"`
	PktsMap *ebpf.Map     `ebpf:"packets"`
}

type packetService struct {
	objs objects
	pkts *perf.Reader

	mu   sync.Mutex
	atch map[string][]link.Link
}

func newPacketService() (*packetService, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf))
	if err != nil {
		return nil, fmt.Errorf("unable to load packet module: %w", err)
	}

	var objs objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("unable to find required objects: %w", err)
	}

	pkts, err := perf.NewReader(objs.PktsMap, 8*1024)
	if err != nil {
		return nil, fmt.Errorf("unable to create map: %w", err)
	}

	return &packetService{
		objs: objs,
		pkts: pkts,
		atch: map[string][]link.Link{},
	}, nil
}

// AttachContainer attaches to the container.
func (s *packetService) AttachContainer(name, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.atch[name]; ok {
		return nil
	}

	var links [2]link.Link
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: s.objs.Ingress,
	})
	if err != nil {
		return fmt.Errorf("attach to container %s on path %q: %w", name, path, err)
	}
	links[0] = l

	l, err = link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: s.objs.Egress,
	})
	if err != nil {
		_ = links[0].Close()
		return fmt.Errorf("attach to container %s on path %q: %w", name, path, err)
	}
	links[1] = l

	s.atch[name] = links[:]

	return nil
}

// DetachContainer detaches the container.
func (s *packetService) DetachContainer(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	links, ok := s.atch[name]
	if !ok {
		return nil
	}

	var errs error
	for _, l := range links {
		if err := l.Close(); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("detach to container %s: %w", name, err))
		}
	}

	delete(s.atch, name)

	return errs
}

// Watch reads packets from perf events.
func (s *packetService) Watch(pktFn func(pkt packet), lostFn func(cnt uint64)) {
	// This may need to be scaled up to keep up with full load.
	for {
		rec, err := s.pkts.Read()
		if err != nil {
			return
		}

		if rec.RawSample == nil {
			lostFn(rec.LostSamples)
			continue
		}

		pktFn(toPacket(rec.RawSample))
	}
}

// Close detaches all containers and closes the packet module.
func (s *packetService) Close() error {
	var errs error

	for name := range s.atch {
		err := s.DetachContainer(name)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	err := s.objs.Ingress.Close()
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	err = s.objs.Egress.Close()
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	err = s.pkts.Close()
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	return errs
}
