package ebpf

import (
	"time"

	"github.com/hamba/logger"
	"github.com/nrwiersma/ebpf/containers"
)

// Containers represents a container service.
type Containers interface {
	Events() <-chan containers.ContainerEvent
	Name(ip [16]byte) string
}

// App is the core orchestrator.
type App struct {
	ctrs Containers

	pkts *packetService
	mtrs *metricService

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

	app.mtrs = newMetricsService(10*time.Second, app.handleMetrics)

	go pkts.Watch(app.handlePacket, app.handleLost)

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
	var (
		sip, rip  [16]byte
		bin, bout uint64
	)
	switch {
	case pkt.Flags&flagIn == flagIn:
		sip = pkt.DestIP
		rip = pkt.SrcIP
		bin = uint64(pkt.Len)
	case pkt.Flags&flagOut == flagOut:
		sip = pkt.SrcIP
		rip = pkt.DestIP
		bout = uint64(pkt.Len)
	default:
		a.log.Error("Unknown direction", "pkt", pkt)
	}

	// This is naive but in general true.
	port := pkt.SrcPort
	if pkt.DestPort < port {
		port = pkt.DestPort
	}

	var proto string
	switch pkt.Protocol {
	case protoUDP:
		proto = "UDP"
	case protoTCP:
		proto = "TCP"
	}

	rec := record{
		Timestamp: pkt.Timestamp,
		Subject:   a.ctrs.Name(sip),
		Remote:    a.ctrs.Name(rip),
		Port:      port,
		Protocol:  proto,
		BytesIn:   bin,
		BytesOut:  bout,
		RTT:       float64(pkt.RTT) / 1000000, // Convert to ms.
	}

	a.mtrs.Add(rec)
}

func (a *App) handleMetrics(ms []metric) {
	for _, m := range ms {
		a.log.Info("Got",
			"time", m.Timestamp,
			"subj", m.Subject,
			"remo", m.Remote,
			"port", m.Port,
			"proto", m.Protocol,
			"out", m.BytesOut,
			"in", m.BytesIn,
			"rtt p50", m.RTT.Quantile(0.5),
			"rtt p90", m.RTT.Quantile(0.9),
			"rtt p95", m.RTT.Quantile(0.95),
		)
	}
}

func (a *App) handleLost(cnt uint64) {
	a.log.Error("Lost events", "count", cnt)
}

func (a *App) Close() error {
	close(a.doneCh)

	_ = a.pkts.Close()

	return a.mtrs.Close()
}
