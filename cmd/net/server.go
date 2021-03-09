package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/urfave/cli/v2"
)

func runServer(c *cli.Context) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	h := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(rw, req.Body)
	})

	addr := c.String(flagAddr)
	srv := http.Server{
		Addr:    addr,
		Handler: h,
	}
	log.Printf("Listening on %s\n", addr)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("Server closed", err)
		}
	}()

	<-ctx.Done()

	_ = srv.Close()

	return nil
}
