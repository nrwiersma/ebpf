package main

import (
	"log"
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/urfave/cli/v2"
)

var version = "¯\\_(ツ)_/¯"

const (
	flagAddr = "addr"

	flagURI = "uri"
)

var commands = []*cli.Command{
	{
		Name:  "server",
		Usage: "Run the server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    flagAddr,
				Usage:   "Address to listen to",
				EnvVars: []string{"ADDR"},
				Value:   ":80",
			},
		},
		Action: runServer,
	},
	{
		Name:  "client",
		Usage: "Run the client",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    flagURI,
				Usage:   "URI to connect to",
				EnvVars: []string{"URI"},
			},
		},
		Action: runClient,
	},
}

func main() {
	app := &cli.App{
		Name:     "app",
		Version:  version,
		Commands: commands,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
