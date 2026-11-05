// tailpocket-host runs the host SDK for apps not written in Go: the app spawns it and talks
// line-delimited JSON over stdin/stdout. Protocol: docs/HOST-IPC.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := Run(ctx, os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
