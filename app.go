package ebpf

import (
	"time"

	"github.com/hamba/logger"
	"github.com/nrwiersma/ebpf/container"
	"github.com/nrwiersma/ebpf/packet"
)

// Containers represents a container service.
type Containers interface {
	Events() <-chan container.Event
	Name(ip [16]byte) string
	Close() error
}

type Packets interface {
	AttachContainer(name, path string) error
	DetachContainer(name string) error
	Watch(pktFn func(pkt packet.Packet), lostFn func(cnt uint64))
}

// App is the core orchestrator.
type App struct {
	ctrs Containers
	pkts Packets

	mtrs *metricService

	doneCh chan struct{}

	log logger.Logger
}

// NewApp returns an application.
func NewApp(ctrs Containers, pkts Packets, log logger.Logger) (*App, error) {
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
		var evnt container.Event
		select {
		case <-a.doneCh:
			return
		case evnt = <-events:
		}

		switch evnt.Type {
		case container.Added:
			if err := a.pkts.AttachContainer(evnt.Name, evnt.CGroupPath); err != nil {
				a.log.Error("Unable to attach to container", "error", err)
			}
		case container.Removed:
			if err := a.pkts.DetachContainer(evnt.Name); err != nil {
				a.log.Error("Unable to detach to container", "error", err)
			}
		default:
			a.log.Error("Unable to to handle container event", "event", evnt.Type)
		}
	}
}

func (a *App) handlePacket(pkt packet.Packet) {
	var (
		sip, rip  [16]byte
		bin, bout uint64
	)
	switch {
	case pkt.Flags&packet.FlagIn == packet.FlagIn:
		sip = pkt.DestIP
		rip = pkt.SrcIP
		bin = uint64(pkt.Len)
	case pkt.Flags&packet.FlagOut == packet.FlagOut:
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
	switch pkt.Proto {
	case packet.ProtoUDP:
		proto = "UDP"
	case packet.ProtoTCP:
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

// Close closes the application.
func (a *App) Close() error {
	close(a.doneCh)

	return a.mtrs.Close()
}
