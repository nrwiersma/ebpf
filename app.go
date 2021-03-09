package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/iovisor/gobpf/elf"
)

import "C"

//go:embed bpf/dist/metrics.o
var bpf []byte

type App struct {
	mod    *elf.Module
	client *docker.Client

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

	client, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("unable to connect to docker: %w", err)
	}

	app := &App{
		mod:     mod,
		client:  client,
		cgroups: map[string]string{},
	}

	go app.watchContainers()

	go app.watchMap()

	return app, nil
}

func (a *App) watchContainers() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-a.doneCh:
			return
		case <-tick.C:
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		containers, err := a.client.ContainerList(ctx, types.ContainerListOptions{})
		cancel()
		if err != nil {
			log.Println(err)
			continue
		}

		a.mu.Lock()
		for _, ctr := range containers {
			id := ctr.ID
			if _, ok := a.cgroups[id]; ok {
				continue
			}

			a.watchContainer(id)
		}
		a.mu.Unlock()
	}
}

func (a *App) watchMap() {
	mp := a.mod.Map("count")

	packets_key := 0
	bytes_key := 1

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	var packets, bytes uint64
	for {
		select {
		case <-a.doneCh:
			return
		case <-tick.C:
		}

		if err := a.mod.LookupElement(mp, unsafe.Pointer(&packets_key), unsafe.Pointer(&packets)); err != nil {
			fmt.Printf("error looking up in map: %v\n", err)
		}

		if err := a.mod.LookupElement(mp, unsafe.Pointer(&bytes_key), unsafe.Pointer(&bytes)); err != nil {
			fmt.Printf("error looking up in map: %v\n", err)
		}

		fmt.Println("cgroup received", packets, "packets and", bytes, "bytes")
	}
}

func (a *App) watchContainer(id string) {
	defer func() {
		if v := recover(); v != nil {
			fmt.Printf("recovered from panic: %v\n", v)
		}
	}()

	fmt.Printf("attaching container %s\n", id)

	path, err := a.findCgroupPath(id)
	if err != nil {
		fmt.Println("find cgroup path", err)
		return
	}

	fmt.Printf("found container cgroup %s\n", path)

	a.mu.Lock()
	defer a.mu.Unlock()

	for prog := range a.mod.IterCgroupProgram() {
		fmt.Printf("attaching prog %s\n", prog.Name)

		if err = elf.AttachCgroupProgram(prog, path, elf.IngressType|elf.EgressType); err != nil {
			fmt.Println("attach", err)
		}
	}

	fmt.Printf("attached container %s\n", id)

	a.cgroups[id] = path
}

var cgroupPaths = []string{
	"/sys/fs/cgroup/memory/docker/%s/",
	"/sys/fs/cgroup/memory/system.slice/docker-%s.scope/",
	"/sys/fs/cgroup/docker/%s/",
	"/sys/fs/cgroup/system.slice/docker-%s.scope/",
}

func (a *App) findCgroupPath(id string) (string, error) {
	for _, p := range cgroupPaths {
		path := fmt.Sprintf(p, id)

		if _, err := os.Stat(path); err != nil {
			continue
		}
		return path, nil
	}

	return "", os.ErrNotExist
}

func (a *App) Close() error {
	close(a.doneCh)

	for prog := range a.mod.IterCgroupProgram() {
		for id, path := range a.cgroups {
			if err := elf.DetachCgroupProgram(prog, path, elf.IngressType|elf.EgressType); err != nil {
				fmt.Println("detach", err)
			}

			fmt.Printf("detached container %s\n", id)
		}
	}

	if err := a.mod.Close(); err != nil {
		return err
	}

	return nil
}
