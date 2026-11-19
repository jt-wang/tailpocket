// Command tailpocket-relay is a relay you run yourself on a machine both your
// phone and your computer can reach. Phone and computer both dial out to
// it, and it copies their already-encrypted bytes between them.
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
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jt-wang/tailpocket/connectrelay"
)

// Set at build time with -ldflags "-X main.version=…".
var version = "dev"

// idleTimeout closes a keep-alive connection that stays quiet between
// requests; a var so a test need not wait.
var idleTimeout = 60 * time.Second

// fileLimit reads the open-file limit; a var so a test can set it.
var fileLimit = openFileLimit

// minToken is the shortest token accepted, in bytes.
const minToken = 16

// maxHeaderBytes bounds a request's headers; the relay's own requests need well under 1 KiB.
const maxHeaderBytes = 8 << 10

const tokenHelp = `tailpocket-relay needs a token so only your computer can register.
Make one and pass it as a file or an environment variable:

  openssl rand -base64 32 > relay.token && chmod 600 relay.token
  tailpocket-relay --token-file relay.token --public-host relay.example.com

  TAILPOCKET_RELAY_TOKEN="$(openssl rand -base64 32)" tailpocket-relay --public-host relay.example.com`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

type prefixes []netip.Prefix

func (p *prefixes) String() string {
	s := make([]string, len(*p))
	for i, x := range *p {
		s[i] = x.String()
	}
	return strings.Join(s, ",")
}

func (p *prefixes) Set(v string) error {
	x, err := netip.ParsePrefix(strings.TrimSpace(v))
	if err != nil {
		return err
	}
	*p = append(*p, x.Masked())
	return nil
}

// run is main without the process: it returns the exit code. 2 means the
// arguments or the token setup are wrong; ctx ending stops the relay.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tailpocket-relay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		listen     = fs.String("listen", "127.0.0.1:8080", "address to listen on")
		tokenFile  = fs.String("token-file", "", "file holding the relay token (one line); or set TAILPOCKET_RELAY_TOKEN")
		tlsCert    = fs.String("tls-cert", "", "TLS certificate file; with --tls-key, serve wss:// directly")
		tlsKey     = fs.String("tls-key", "", "TLS key file")
		maxRooms   = fs.Int("max-rooms", connectrelay.DefaultMaxRooms, "most hosts registered at once")
		maxPhones  = fs.Int("max-phones-per-room", connectrelay.DefaultMaxPhonesPerRoom, "most phone connections per computer")
		phoneRate  = fs.Int("phone-rate", connectrelay.DefaultPhoneRate, "phone connections per source IP per minute")
		maxConns   = fs.Int("max-conns", connectrelay.DefaultMaxConns, "most TCP connections at once")
		publicHost = fs.String("public-host", "", "required: the relay's host name phones and computers connect to, e.g. relay.example.com (a port is allowed and ignored)")
		trustProxy prefixes
		showVer    = fs.Bool("version", false, "print the version and exit")
	)
	fs.Var(&trustProxy, "trust-proxy", "CIDR of a reverse proxy whose X-Forwarded-For is believed (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVer {
		fmt.Fprintf(stdout, "tailpocket-relay %s\n", version)
		return 0
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "tailpocket-relay: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() > 0 {
		return fail("unexpected argument %q", fs.Arg(0))
	}
	if *maxRooms <= 0 || *maxPhones <= 0 || *phoneRate <= 0 || *maxConns <= 0 {
		return fail("--max-rooms, --max-phones-per-room, --phone-rate and --max-conns must be above 0")
	}
	if *publicHost != "" && connectrelay.NormalizeHost(*publicHost) == "" {
		return fail("--public-host %q has no host name", *publicHost)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return fail("--tls-cert and --tls-key go together")
	}

	token := ""
	switch {
	case *tokenFile != "":
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fail("read --token-file: %v", err)
		}
		token = strings.TrimSpace(string(b))
		if token == "" {
			return fail("--token-file %s is empty", *tokenFile)
		}
	case getenv("TAILPOCKET_RELAY_TOKEN") != "":
		token = strings.TrimSpace(getenv("TAILPOCKET_RELAY_TOKEN"))
	}
	if token == "" {
		fmt.Fprintln(stderr, tokenHelp)
		return 2
	}
	if token != "" && len(token) < minToken {
		return fail("the token is %d bytes; use at least %d (openssl rand -base64 32 gives 44)", len(token), minToken)
	}
	if *tokenFile != "" && othersCanRead(*tokenFile) {
		fmt.Fprintf(stderr, "tailpocket-relay: warning: %s is readable by other users; chmod 600 it\n", *tokenFile)
	}
	if *publicHost == "" {
		return fail("--public-host is required: the relay's host name phones and computers connect to, e.g. --public-host relay.example.com.\n" +
			"The computer signs its registration for that name, so another relay cannot pass the signature on.")
	}

	srv, err := connectrelay.NewServer(connectrelay.Config{
		Token:            token,
		MaxRooms:         *maxRooms,
		MaxPhonesPerRoom: *maxPhones,
		PhoneRate:        *phoneRate,
		TrustProxy:       trustProxy,
		PublicHost:       *publicHost,
		MaxConns:         *maxConns,
		Logger:           log.New(stderr, "", 0),
	})
	if err != nil {
		return fail("%v", err)
	}
	defer srv.Close()

	// Each room: one registration, and per phone the phone and its accept.
	if need := *maxRooms * (1 + 2**maxPhones); need > *maxConns {
		fmt.Fprintf(stderr, "tailpocket-relay: warning: --max-rooms %d with --max-phones-per-room %d can use %d connections; raise --max-conns (now %d)\n",
			*maxRooms, *maxPhones, need, *maxConns)
	}
	if n, ok := fileLimit(); ok && n < uint64(*maxConns)+64 {
		fmt.Fprintf(stderr, "tailpocket-relay: warning: this process may have only %d open files, under --max-conns %d plus 64; raise the limit (ulimit -n) or lower --max-conns\n",
			n, *maxConns)
	}

	inner, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail("listen: %v", err)
	}
	ln := srv.Listener(inner)
	hs := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
		// Else net/http answers OPTIONS * itself; the relay refuses it with everything not origin-form.
		DisableGeneralOptionsHandler: true,
		// Upgraded WebSocket connections are hijacked and not affected.
		IdleTimeout: idleTimeout,
		ErrorLog:    log.New(io.Discard, "", 0),
	}
	if *tlsCert != "" {
		certs := &certFiles{cert: *tlsCert, key: *tlsKey}
		if _, err := certs.get(nil); err != nil {
			ln.Close()
			return fail("TLS certificate: %v", err)
		}
		hs.TLSConfig = &tls.Config{GetCertificate: certs.get}
	}
	scheme := "ws"
	if *tlsCert != "" {
		scheme = "wss"
	} else {
		fmt.Fprintln(stderr, "tailpocket-relay: serving plain ws://; put it behind a TLS reverse proxy (wss://) before phones use it over the internet")
	}
	fmt.Fprintf(stderr, "tailpocket-relay %s listening on %s (%s)\n", version, ln.Addr(), scheme)

	errc := make(chan error, 1)
	go func() {
		if *tlsCert != "" {
			errc <- hs.ServeTLS(ln, "", "")
		} else {
			errc <- hs.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "tailpocket-relay: %v\n", err)
			return 1
		}
		return 0
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Close()
	_ = hs.Shutdown(sctx)
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
