// Command tailpocket-push is a push gateway. Computers send it push notes
// already sealed for one phone (package connectpush), and it passes them to
// APNs or FCM with the publisher's credentials. It keeps no database and
// can neither read the notes nor send to a device that did not register.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Set at build time with -ldflags "-X main.version=…".
var version = "dev"

const configHelp = `tailpocket-push needs a config file:

  tailpocket-push --config push.json

See cmd/tailpocket-push/README.md for what goes in it.`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: it returns the exit code. 2 means the
// arguments or the config are wrong; ctx ending stops the gateway.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tailpocket-push", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath = fs.String("config", "", "required: the JSON config file")
		listen     = fs.String("listen", "", "address to listen on; overrides listen in the config")
		showVer    = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVer {
		fmt.Fprintf(stdout, "tailpocket-push %s\n", version)
		return 0
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "tailpocket-push: "+format+"\n", a...)
		return 2
	}
	warn := func(format string, a ...any) {
		fmt.Fprintf(stderr, "tailpocket-push: "+format+"\n", a...)
	}
	if fs.NArg() > 0 {
		return fail("unexpected argument %q", fs.Arg(0))
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, configHelp)
		return 2
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fail("%v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	keys, err := loadHandleKeys(cfg, warn)
	if err != nil {
		return fail("%v", err)
	}
	gens, err := loadGenStore(cfg.StateFile)
	if err != nil {
		return fail("%v", err)
	}
	up := defaultUpstream()
	apps, err := loadApps(cfg, up, gens, warn)
	if err != nil {
		return fail("%v", err)
	}
	srv := newServer(cfg, keys, gens, apps, up, log.New(stderr, "", log.LstdFlags|log.LUTC))

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail("listen: %v", err)
	}
	hs := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      upstreamTimeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// "OPTIONS *" goes to the handler, which refuses it, like any
		// request target that is not a path.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(io.Discard, "", 0),
	}
	if cfg.TLSCert != "" {
		certs := &certFiles{cert: cfg.TLSCert, key: cfg.TLSKey}
		if _, err := certs.get(nil); err != nil {
			ln.Close()
			return fail("TLS certificate: %v", err)
		}
		hs.TLSConfig = &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12}
	}
	scheme := "https"
	if cfg.TLSCert == "" {
		scheme = "http"
		warn("serving plain http://; put it behind a TLS reverse proxy before computers use it over the internet")
	}
	ids := make([]string, 0, len(cfg.Apps))
	for _, a := range cfg.Apps {
		ids = append(ids, a.ID)
	}
	fmt.Fprintf(stderr, "tailpocket-push %s listening on %s (%s), apps %v\n", version, ln.Addr(), scheme, ids)

	sctx, stopSweep := context.WithCancel(ctx)
	defer stopSweep()
	go srv.sweepEvery(sctx, time.Minute)

	errc := make(chan error, 1)
	go func() {
		if cfg.TLSCert != "" {
			errc <- hs.ServeTLS(ln, "", "")
		} else {
			errc <- hs.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "tailpocket-push: %v\n", err)
			return 1
		}
		return 0
	case <-ctx.Done():
	}
	shctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(shctx)
	return 0
}

// certFiles serves the certificate in two files and loads them again when
// either changes, so a renewed certificate is used without a restart.
type certFiles struct {
	cert, key string

	mu      sync.Mutex
	stamp   string
	current *tls.Certificate
}

func (c *certFiles) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	stamp := ""
	for _, p := range []string{c.cert, c.key} {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		stamp += fmt.Sprintf("%d/%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil && stamp == c.stamp {
		return c.current, nil
	}
	pair, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		if c.current != nil {
			// Half-written renewal: keep serving the old one.
			return c.current, nil
		}
		return nil, err
	}
	c.current, c.stamp = &pair, stamp
	return c.current, nil
}
