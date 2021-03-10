package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/nrwiersma/ebpf"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

func runAgent(c *cli.Context) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	memlockLimit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, memlockLimit)

	app, err := ebpf.NewApp()
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()

	<-ctx.Done()

	return nil
}
