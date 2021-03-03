package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

import _ "github.com/joho/godotenv/autoload"

var version = "¯\\_(ツ)_/¯"

func main() {
	app := &cli.App{
		Name:    "agent",
		Version: version,
		Action:  runAgent,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
