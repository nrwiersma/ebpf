package main

import (
	"os"
	"time"

	"github.com/hamba/logger"
	"github.com/nrwiersma/ebpf"
	"github.com/nrwiersma/ebpf/containers/k8s"
	"github.com/urfave/cli/v2"
)

func newLogger(c *cli.Context) (logger.Logger, error) {
	str := c.String(flagLogLevel)
	if str == "" {
		str = "info"
	}

	lvl, err := logger.LevelFromString(str)
	if err != nil {
		return nil, err
	}

	h := logger.LevelFilterHandler(
		lvl,
		logger.BufferedStreamHandler(os.Stdout, 1024, time.Second, logger.ConsoleFormat()),
	)

	return logger.New(h), nil
}

func newContainersProvider(c *cli.Context, cgroupRoot string) (ebpf.Containers, error) {
	node := c.String(flagNode)
	ns := []string{"kube-system", c.String(flagNs)}

	return k8s.New(node, cgroupRoot, ns, k8s.ServiceOpts{ContainerEvents: c.Bool(flagContainers)})
}
