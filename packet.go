package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
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
	flagSyn
	flagFin

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

type packetService struct {
	mod     *elf.Module
	inProg  *elf.CgroupProgram
	outProg *elf.CgroupProgram
	pktMap  *elf.PerfMap

	mu      sync.Mutex
	cgroups map[string]string

	pktsCh chan []byte
	lostCh chan uint64
}

func newPacketService() (*packetService, error) {
	mod := elf.NewModuleFromReader(bytes.NewReader(bpf))

	err := mod.Load(map[string]elf.SectionParams{})
	if err != nil {
		return nil, fmt.Errorf("unable to load packet module: %w", err)
	}

	inProg := mod.CgroupProgram("cgroup/skb/ingress")
	if inProg == nil {
		return nil, errors.New("unable to find ingress program")
	}
	outProg := mod.CgroupProgram("cgroup/skb/egress")
	if outProg == nil {
		return nil, errors.New("unable to find egress program")
	}

	pktsCh := make(chan []byte, 100)
	lostCh := make(chan uint64, 100)
	pktMap, err := elf.InitPerfMap(mod, "packets", pktsCh, lostCh)
	if err != nil {
		return nil, fmt.Errorf("unable to load map: %w", err)
	}

	return &packetService{
		mod:     mod,
		inProg:  inProg,
		outProg: outProg,
		pktMap:  pktMap,
		cgroups: map[string]string{},
		pktsCh:  pktsCh,
		lostCh:  lostCh,
	}, nil
}

// AttachContainer attaches to the container.
func (s *packetService) AttachContainer(name, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.cgroups[name]; ok {
		return nil
	}

	if err := elf.AttachCgroupProgram(s.inProg, path, elf.IngressType); err != nil {
		return fmt.Errorf("attach to container %s on path %q: %w", name, path, err)
	}
	if err := elf.AttachCgroupProgram(s.outProg, path, elf.EgressType); err != nil {
		return fmt.Errorf("attach to container %s on path %q: %w", name, path, err)
	}

	s.cgroups[name] = path

	return nil
}

// DetachContainer detaches to the container.
func (s *packetService) DetachContainer(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.cgroups[name]; ok {
		return nil
	}

	path := s.cgroups[name]
	if err := elf.DetachCgroupProgram(s.inProg, path, elf.IngressType); err != nil {
		return fmt.Errorf("detach to container %s on path %q: %w", name, path, err)
	}
	if err := elf.DetachCgroupProgram(s.outProg, path, elf.EgressType); err != nil {
		return fmt.Errorf("detach to container %s on path %q: %w", name, path, err)
	}

	delete(s.cgroups, name)

	return nil
}

func (s *packetService) Watch(pktFn func(pkt packet), lostFn func(cnt uint64), stopCh <-chan struct{}) {
	s.pktMap.SetTimestampFunc(func(data *[]byte) uint64 {
		eventC := (*C.struct_pkt_entry)(unsafe.Pointer(&(*data)[0]))
		return uint64(eventC.ts) + 100*1000 // Delay data by 100us so not out of order.
	})

	s.pktMap.PollStart()
	defer s.pktMap.PollStop()

	// This may need to be scaled up to keep up with full load.
	for {
		select {
		case <-stopCh:
			return
		case raw, ok := <-s.pktsCh:
			if !ok {
				return
			}
			pktFn(toPacket(&raw))
		case lost, ok := <-s.lostCh:
			if !ok {
				return
			}
			lostFn(lost)
		}
	}
}

func toPacket(raw *[]byte) packet {
	var pkt packet

	pktC := (*C.struct_pkt_entry)(unsafe.Pointer(&(*raw)[0]))

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
	for name := range s.cgroups {
		_ = s.DetachContainer(name)
	}

	if err := s.mod.Close(); err != nil {
		return fmt.Errorf("unable to close packet module: %w", err)
	}

	close(s.pktsCh)
	close(s.lostCh)

	return nil
}
