package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

import _ "github.com/joho/godotenv/autoload"

var version = "¯\\_(ツ)_/¯"

const (
	flagLogLevel = "log.level"

	flagNode       = "node"
	flagNs         = "namespace"
	flagContainers = "containers"
)

func main() {
	app := &cli.App{
		Name:    "agent",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    flagLogLevel,
				Value:   "info",
				Usage:   "Specify the log level. E.g. 'debug', 'info', 'error'.",
				EnvVars: []string{"LOG_LEVEL"},
			},

			&cli.StringFlag{
				Name:     flagNode,
				Aliases:  []string{"n"},
				Usage:    "The current kubernetes node name.",
				EnvVars:  []string{"NODE"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     flagNs,
				Aliases:  []string{"ns"},
				Usage:    "The current kubernetes namespace of the pod.",
				EnvVars:  []string{"NAMESPACE"},
				Required: true,
			},
			&cli.BoolFlag{
				Name:    flagContainers,
				Usage:   "Monitor containers instead of pods.",
				EnvVars: []string{"CONTAINERS"},
			},
		},
		Action: runAgent,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
