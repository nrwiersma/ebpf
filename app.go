package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/hamba/logger"
	"github.com/iovisor/gobpf/elf"
	"github.com/nrwiersma/ebpf/containers"
	"inet.af/netaddr"
)

import "C"

/*
#include <linux/bpf.h>
#include "bpf/metrics.h"
*/
import "C"

//go:embed bpf/dist/metrics.o
var bpf []byte

type event struct {
	Timestamp uint64
	SrcIP     netaddr.IP
	DestIP    netaddr.IP
	SrcPort   uint16
	DestPort  uint16
	Seq       uint32
	AckSeq    uint32
	DataLen   uint32
	Flags     string
	Direction string
}

func eventToGo(data *[]byte) event {
	var evnt event

	raw := make([]byte, len(*data))
	copy(raw, *data)

	eventC := (*C.struct_event_t)(unsafe.Pointer(&raw[0]))

	evnt.Timestamp = uint64(eventC.ts)
	evnt.SrcIP = toIP(uint32(eventC.src_ip))
	evnt.DestIP = toIP(uint32(eventC.dest_ip))
	evnt.SrcPort = uint16(eventC.src_port)
	evnt.DestPort = uint16(eventC.dest_port)
	evnt.Seq = uint32(eventC.seq)
	evnt.AckSeq = uint32(eventC.ack_seq)
	evnt.DataLen = uint32(eventC.len)

	evnt.Direction = "IN"
	if uint16(eventC.direction) == 2 {
		evnt.Direction = "OUT"
	}

	flags := uint16(eventC.flags)
	if flags&1 == 1 {
		evnt.Flags += "SYN "
	}
	if flags&2 == 2 {
		evnt.Flags += "ACK "
	}
	if flags&4 == 4 {
		evnt.Flags += "FIN "
	}

	return evnt
}

// Containers represents a container service.
type Containers interface {
	Events() <-chan containers.ContainerEvent
	Name(ip uint32, port uint16) string
}

// App is the core orchestrator.
type App struct {
	mod  *elf.Module
	ctrs Containers

	mu      sync.Mutex
	cgroups map[string]string

	doneCh chan struct{}

	log logger.Logger
}

// NewApp returns an application.
func NewApp(ctrs Containers, log logger.Logger) (*App, error) {
	mod := elf.NewModuleFromReader(bytes.NewReader(bpf))

	err := mod.Load(map[string]elf.SectionParams{})
	if err != nil {
		return nil, fmt.Errorf("unable to load module: %w", err)
	}

	app := &App{
		mod:     mod,
		ctrs:    ctrs,
		cgroups: map[string]string{},
		log:     log,
	}

	go app.watchContainers()

	go app.watchTable()

	return app, nil
}

func (a *App) watchContainers() {
	events := a.ctrs.Events()

	for {
		var evnt containers.ContainerEvent
		select {
		case <-a.doneCh:
			return
		case evnt = <-events:
		}

		a.mu.Lock()
		switch evnt.Type {
		case containers.Added:
			a.attachPod(evnt.Name, evnt.CGroupPath)
		default:
			a.detachPod(evnt.Name)
		}
		a.mu.Unlock()
	}
}

func (a *App) attachPod(name, path string) {
	if _, ok := a.cgroups[name]; ok {
		return
	}

	attached := false
	inProg := a.mod.CgroupProgram("cgroup/skb/ingress")
	outProg := a.mod.CgroupProgram("cgroup/skb/egress")

	if inProg != nil {
		if err := elf.AttachCgroupProgram(inProg, path, elf.IngressType); err != nil {
			a.log.Error("Unable to attach to pod", "pod", name, "path", path, "error", err)
		}
		attached = true
	} else {
		a.log.Error("Unable to find ingress prog")
	}

	if outProg != nil {
		if err := elf.AttachCgroupProgram(outProg, path, elf.EgressType); err != nil {
			a.log.Error("Unable to attach to pod", "pod", name, "path", path, "error", err)
		}
		attached = true
	} else {
		a.log.Error("Unable to find egress prog")
	}

	if !attached {
		return
	}

	a.log.Debug("Attached pod", "pod", name)

	a.cgroups[name] = path
}

func (a *App) detachPod(name string) {
	if _, ok := a.cgroups[name]; !ok {
		return
	}

	path := a.cgroups[name]
	inProg := a.mod.CgroupProgram("cgroup/skb/ingress")
	outProg := a.mod.CgroupProgram("cgroup/skb/egress")

	if inProg != nil {
		if err := elf.DetachCgroupProgram(inProg, path, elf.IngressType); err != nil {
			a.log.Error("Unable to detach to pod", "pod", name, "path", path, "error", err)
		}
	} else {
		a.log.Error("Unable to find ingress prog")
	}

	if outProg != nil {
		if err := elf.DetachCgroupProgram(outProg, path, elf.EgressType); err != nil {
			a.log.Error("Unable to detach to pod", "pod", name, "path", path, "error", err)
		}
	} else {
		a.log.Error("Unable to find egress prog")
	}
}

func (a *App) watchTable() {
	eventsCh := make(chan []byte, 100)
	lostCh := make(chan uint64, 100)
	defer func() {
		close(eventsCh)
		close(lostCh)
	}()

	mp, err := elf.InitPerfMap(a.mod, "events", eventsCh, lostCh)
	if err != nil {
		a.log.Error("Unable to load map", "error", err)
	}
	mp.SetTimestampFunc(func(data *[]byte) uint64 {
		eventC := (*C.struct_event_t)(unsafe.Pointer(&(*data)[0]))
		return uint64(eventC.ts) + 100000 // Delay data a little so not out of order.
	})

	mp.PollStart()
	defer mp.PollStop()

	for {
		select {
		case <-a.doneCh:
			return
		case data, ok := <-eventsCh:
			if !ok {
				return
			}

			evnt := eventToGo(&data)

			a.log.Info("Got", "event", evnt)
		case lost, ok := <-lostCh:
			if !ok {
				return
			}

			a.log.Warn("Lost events", "count", lost)
		}
	}
}

func (a *App) Close() error {
	close(a.doneCh)

	a.mu.Lock()
	for name := range a.cgroups {
		a.detachPod(name)
	}
	a.mu.Unlock()

	if err := a.mod.Close(); err != nil {
		return err
	}

	return nil
}

func toIP(raw uint32) netaddr.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], raw)
	return netaddr.IPv4(b[0], b[1], b[2], b[3])
}
