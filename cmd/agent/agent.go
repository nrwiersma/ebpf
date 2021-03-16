package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/nrwiersma/ebpf"
	"github.com/nrwiersma/ebpf/pkg/cgroups"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
	"github.com/hamba/logger"
)

func runAgent(c *cli.Context) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	memlockLimit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, memlockLimit)

	if err := cgroups.EnsureCgroupFS(""); err != nil {
		return err
	}

	log := createLogger()

	app, err := ebpf.NewApp(log)
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()

	<-ctx.Done()

	return nil
}

func createLogger() logger.Logger {
	h := logger.LevelFilterHandler(
		logger.Info,
		logger.BufferedStreamHandler(os.Stdout, 1024, time.Second, logger.ConsoleFormat()),
	)

	return  logger.New(h)
}
