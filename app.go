package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"
	"time"

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
		mod:    mod,
		client: client,
	}

	mod.

	go app.watchContainers()

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
	}
}

func (a *App) Close() error {
	return nil
}
