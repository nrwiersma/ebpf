package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/nrwiersma/ebpf/pkg/cgroups"
	"github.com/nrwiersma/ebpf/pkg/k8s"
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
}

func eventToGo(data *[]byte) event {
	var evnt event

	eventC := (*C.struct_event_t)(unsafe.Pointer(&(*data)[0]))

	evnt.Timestamp = uint64(eventC.ts)
	evnt.SrcIP = toIP(uint32(eventC.src_ip))
	evnt.DestIP = toIP(uint32(eventC.dest_ip))
	evnt.SrcPort = uint16(eventC.src_port)
	evnt.DestPort = uint16(eventC.dest_port)
	evnt.Seq = uint32(eventC.seq)
	evnt.AckSeq = uint32(eventC.ack_seq)
	evnt.DataLen = uint32(eventC.len)
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

type App struct {
	mod *elf.Module

	mu      sync.Mutex
	cgroups map[string]string

	doneCh chan struct{}
}

func NewApp() (*App, error) {
	mod := elf.NewModuleFromReader(bytes.NewReader(bpf))

	err := mod.Load(map[string]elf.SectionParams{})
	if err != nil {
		return nil, fmt.Errorf("unable to load module: %w", err)
	}

	app := &App{
		mod:     mod,
		cgroups: map[string]string{},
	}

	go app.watchContainers()

	go app.watchTable()
	//go app.watchMap()

	return app, nil
}

func (a *App) watchContainers() {
	events := make(chan k8s.Event, 100)
	defer close(events)

	if err := k8s.WatchPodEvents(events, a.doneCh); err != nil {
		fmt.Printf("Cannot watch for pods: %v", err)
	}

	for event := range events {
		if event.Namespace != "app" {
			fmt.Printf("Ignoring pod %s\n", event.FullName)
			continue
		}

		path := k8s.GetCGroupPath(cgroups.CgroupRoot(), event.PodUID, event.PodQOSClass)

		a.mu.Lock()
		switch event.Status {
		case k8s.RunningStatus:
			a.attachPod(event.FullName, path)
		default:
			a.detachPod(event.FullName)
		}
		a.mu.Unlock()
	}
}

func (a *App) watchTable() {
	eventsCh := make(chan []byte)
	lostCh := make(chan uint64)
	defer func() {
		close(eventsCh)
		close(lostCh)
	}()

	mp, err := elf.InitPerfMap(a.mod, "events", eventsCh, lostCh)
	if err != nil {
		fmt.Printf("error loading perf map: %v\n", err)
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
			fmt.Printf("EVENT: %+v\n", evnt)
		case lost, ok := <-lostCh:
			if !ok {
				return
			}

			fmt.Println("LOST: ", lost)
		}
	}
}

func (a *App) updateMap(mp *elf.Map, key uint32, value uint64) error {
	return a.mod.UpdateElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
}

func (a *App) lookupMap(mp *elf.Map, key uint32) (uint64, error) {
	var value uint64
	if err := a.mod.LookupElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return 0, err
	}
	return value, nil
}

func (a *App) attachPod(name, path string) {
	if _, ok := a.cgroups[name]; ok {
		return
	}

	fmt.Printf("attaching pod %s\n", name)

	attached := false
	for prog := range a.mod.IterCgroupProgram() {
		if err := elf.AttachCgroupProgram(prog, path, elf.IngressType|elf.EgressType); err != nil {
			fmt.Println("attach", err)
			continue
		}
		attached = true
	}

	if !attached {
		return
	}

	fmt.Printf("attached pod %s\n", name)

	a.cgroups[name] = path
}

func (a *App) detachPod(name string) {
	if _, ok := a.cgroups[name]; !ok {
		return
	}

	path := a.cgroups[name]
	for prog := range a.mod.IterCgroupProgram() {
		if err := elf.DetachCgroupProgram(prog, path, elf.IngressType|elf.EgressType); err != nil {
			fmt.Println("detach", err)
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
