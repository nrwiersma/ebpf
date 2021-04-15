package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/nrwiersma/ebpf"
	"github.com/nrwiersma/ebpf/pkg/cgroups"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

func runAgent(c *cli.Context) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	log, err := newLogger(c)
	if err != nil {
		return err
	}

	memlockLimit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, memlockLimit)
	if err != nil {
		return err
	}

	if err := cgroups.EnsureCgroupFS(""); err != nil {
		return err
	}

	ctrs, err := newContainersProvider(c, cgroups.CgroupRoot())
	if err != nil {
		return err
	}
	defer ctrs.Close()

	app, err := ebpf.NewApp(ctrs, log)
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()

	<-ctx.Done()

	return nil
}
