package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/nrwiersma/ebpf"
	"github.com/urfave/cli/v2"
)

func runAgent(c *cli.Context) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	app, err := ebpf.NewApp()
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()

	<-ctx.Done()

	return nil
}
