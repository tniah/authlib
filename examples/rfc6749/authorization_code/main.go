package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/tniah/authlib/examples/config"
)

func main() {
	cfg := config.FromEnvVars(nil)
	lg := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}))

	handler, err := SetupServer(lg)
	if err != nil {
		lg.Error("failed to set up server", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Address, cfg.Port),
		Handler: handler,
	}

	lg.Info("server listening, press ctrl+c to stop", "addr", srv.Addr)
	if !errors.Is(srv.ListenAndServe(), http.ErrServerClosed) {
		lg.Error("server closed unexpectedly")
		os.Exit(1)
	}
}
