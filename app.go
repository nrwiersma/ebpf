package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/nrwiersma/ebpf/pkg/cgroups"
	"github.com/nrwiersma/ebpf/pkg/k8s"
)

import "C"

//go:embed bpf/dist/metrics.o
var bpf []byte

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

	go app.watchMap()

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
		switch event.Type {
		case k8s.NewPodEvent:
			a.attachPod(event.FullName, path)
		case k8s.DeletePodEvent:
			a.detachPod(event.FullName)
		}
		a.mu.Unlock()
	}
}

func (a *App) watchMap() {
	mp := a.mod.Map("count")

	packets_key := uint32(0)
	syn_key := uint32(1)
	bytes_key := uint32(3)

	if err := a.updateMap(mp, packets_key, 0); err != nil {
		fmt.Printf("error updating map: %v\n", err)
	}
	if err := a.updateMap(mp, syn_key, 0); err != nil {
		fmt.Printf("error updating map: %v\n", err)
	}
	if err := a.updateMap(mp, bytes_key, 0); err != nil {
		fmt.Printf("error updating map: %v\n", err)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-a.doneCh:
			return
		case <-tick.C:
		}

		packets, err := a.lookupMap(mp, packets_key)
		if err != nil {
			fmt.Printf("error looking up in map: %v\n", err)
		}

		syn, err := a.lookupMap(mp, syn_key)
		if err != nil {
			fmt.Printf("error looking up in map: %v\n", err)
		}

		bytes, err := a.lookupMap(mp, packets_key)
		if err != nil {
			fmt.Printf("error looking up in map: %v\n", err)
		}

		fmt.Println("cgroup received", packets, "packets and", syn, "syns and", bytes, "bytes")
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
