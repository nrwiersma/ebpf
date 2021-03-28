package ebpf

import (
	"github.com/hamba/logger"
	"github.com/nrwiersma/ebpf/containers"
)

// Containers represents a container service.
type Containers interface {
	Events() <-chan containers.ContainerEvent
	Name(ip uint32, port uint16) string
}

// App is the core orchestrator.
type App struct {
	ctrs Containers

	pkts *packetService

	doneCh chan struct{}

	log logger.Logger
}

// NewApp returns an application.
func NewApp(ctrs Containers, log logger.Logger) (*App, error) {
	pkts, err := newPacketService()
	if err != nil {
		return nil, err
	}

	app := &App{
		ctrs:   ctrs,
		pkts:   pkts,
		doneCh: make(chan struct{}),
		log:    log,
	}

	go pkts.Watch(app.handlePacket, app.handleLost, app.doneCh)

	go app.watchContainers()

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

		switch evnt.Type {
		case containers.Added:
			if err := a.pkts.AttachContainer(evnt.Name, evnt.CGroupPath); err != nil {
				a.log.Error("Unable to attach to container", "error", err)
			}
		case containers.Removed:
			if err := a.pkts.DetachContainer(evnt.Name); err != nil {
				a.log.Error("Unable to detach to container", "error", err)
			}
		default:
			a.log.Error("Unable to to handle container event", "event", evnt.Type)
		}
	}
}

func (a *App) handlePacket(pkt packet) {
	a.log.Info("Got", "packet", pkt)
}

func (a *App) handleLost(cnt uint64) {
	a.log.Warn("Lost events", "count", cnt)
}

func (a *App) Close() error {
	close(a.doneCh)

	return a.pkts.Close()
}
