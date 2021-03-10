package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/urfave/cli/v2"
)

func runClient(c *cli.Context) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	uri := c.String(flagURI)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}

			res, err := http.Post(uri, "text/plain", bytes.NewReader([]byte("test")))
			if err != nil {
				fmt.Println("Error", err)
			}
			if res.StatusCode != 200 {
				fmt.Println("could not send request")
			}
		}
	}()

	<-ctx.Done()

	return nil
}
