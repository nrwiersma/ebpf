package main

import (
	"github.com/nrwiersma/ebpf"
	"github.com/nrwiersma/ebpf/containers/k8s"
	"github.com/urfave/cli/v2"
)

func newContainersProvider(c *cli.Context, cgroupRoot string) (ebpf.Containers, error) {
	node := c.String(flagNode)
	ns := []string{"kube-system", c.String(flagNs)}

	return k8s.New(node, cgroupRoot, ns, k8s.ServiceOpts{ContainerEvents: c.Bool(flagContainers)})
}
