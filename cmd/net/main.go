package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

import _ "github.com/joho/godotenv/autoload"

var version = "¯\\_(ツ)_/¯"

var commands = []*cli.Command{
	{
		Name:   "server",
		Usage:  "Run the server",
		Flags:  []cli.Flag{},
		Action: runServer,
	},
	{
		Name:   "client",
		Usage:  "Run the client",
		Flags:  []cli.Flag{},
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
