package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

/*
#include <linux/bpf.h>
#include "bpf/metrics.h"
*/
import "C"

//go:embed bpf/dist/metrics.o
var bpf []byte

const (
	flagIn = 1 << iota
	flagOut
)

const (
	protoUDP = iota + 1
	protoTCP
)

type packet struct {
	Timestamp uint64
	SrcIP     [16]byte
	DestIP    [16]byte
	SrcPort   uint16
	DestPort  uint16
	Len       uint32
	RTT       uint32
	Protocol  uint16
	Flags     uint16
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

	pktsCh chan []byte
	lostCh chan uint64
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

	var links []link.Link
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: s.objs.Ingress,
	})
	if err != nil {
		return fmt.Errorf("attach to container %s on path %q: %w", name, path, err)
	}
	links = append(links, l)

	l, err = link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: s.objs.Egress,
	})
	if err != nil {
		return fmt.Errorf("attach to container %s on path %q: %w", name, path, err)
	}
	links = append(links, l)

	s.atch[name] = links

	return nil
}

// DetachContainer detaches to the container.
func (s *packetService) DetachContainer(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	links, ok := s.atch[name]
	if !ok {
		return nil
	}

	for _, l := range links {
		if err := l.Close(); err != nil {
			return fmt.Errorf("detach to container %s: %w", name, err)
		}
	}

	delete(s.atch, name)

	return nil
}

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

func toPacket(raw []byte) packet {
	var pkt packet

	pktC := (*C.struct_pkt_entry)(unsafe.Pointer(&raw[0]))

	pkt.Timestamp = uint64(pktC.ts)
	pkt.SrcIP = toIP(pktC.src_ip)
	pkt.DestIP = toIP(pktC.dest_ip)
	pkt.SrcPort = uint16(pktC.src_port)
	pkt.DestPort = uint16(pktC.dest_port)
	pkt.Len = uint32(pktC.len)
	pkt.RTT = uint32(pktC.rtt)
	pkt.Protocol = uint16(pktC.protocol)
	pkt.Flags = uint16(pktC.flags)

	return pkt
}

func toIP(raw [4]C.__be32) [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint32(b[:4], uint32(raw[0]))
	binary.BigEndian.PutUint32(b[4:8], uint32(raw[1]))
	binary.BigEndian.PutUint32(b[8:12], uint32(raw[2]))
	binary.BigEndian.PutUint32(b[12:], uint32(raw[3]))
	return b
}

// Close detaches all containers and closes the packet module.
func (s *packetService) Close() error {
	for name := range s.atch {
		_ = s.DetachContainer(name)
	}

	_ = s.objs.Ingress.Close()
	_ = s.objs.Egress.Close()

	return s.pkts.Close()
}
