// tailpocket-phone is a phone client on the command line: pair with a host, then reach it.
//
//	tailpocket-phone pair [-device NAME] [-prefix tailpocket1:] [-key FILE] [-out FILE] <invite text | ->
//	tailpocket-phone local -service _myapp._tcp [-name HOST] [-device NAME] [-key FILE] [-out FILE]
//	tailpocket-phone connect -link FILE
//	tailpocket-phone dial -link FILE
//
// pair and local print the Link JSON (or write it to -out with mode 0600). The phone key is read
// from -key, or created there if the file does not exist; without -key a new key is used.
// connect prints "listening 127.0.0.1:PORT" and forwards until interrupted; dial pipes stdin/stdout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

const usage = `usage:
  tailpocket-phone pair [-device NAME] [-prefix tailpocket1:] [-key FILE] [-out FILE] <invite text | ->
  tailpocket-phone local -service _myapp._tcp [-name HOST] [-label L] [-device NAME] [-key FILE] [-out FILE]
  tailpocket-phone connect -link FILE
  tailpocket-phone dial -link FILE
`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	device := fs.String("device", hostnameOr("Phone"), "name the host shows")
	prefix := fs.String("prefix", connectinvite.DefaultPrefix, "invite text prefix")
	keyFile := fs.String("key", "", "phone key file")
	outFile := fs.String("out", "", "write the link here")
	service := fs.String("service", "", "Bonjour type")
	name := fs.String("name", "", "host name to pick")
	label := fs.String("label", "", "local pairing label")
	linkFile := fs.String("link", "", "link file")
	derp := fs.String("derp-map-url", "", "own relay map")
	bad := func(msg string) int { fmt.Fprintf(stderr, "%s\n%s", msg, usage); return 2 }
	if err := fs.Parse(args[1:]); err != nil {
		return bad(err.Error())
	}
	opts := connectphone.Options{Device: *device, DERPMapURL: *derp}
	fail := func(err error) int { fmt.Fprintln(stderr, "error:", err); return 1 }

	switch args[0] {
	case "pair":
		if fs.NArg() != 1 {
			return bad("pair needs the invite text")
		}
		text := fs.Arg(0)
		if text == "-" {
			b, _ := io.ReadAll(io.LimitReader(stdin, connectinvite.MaxTextLength+1))
			text = string(b)
		}
		inv, err := connectinvite.Decode(text, *prefix)
		if err != nil {
			return fail(err)
		}
		return finish(ctx, inv, *keyFile, *outFile, opts, stdout, stderr)
	case "local":
		if *service == "" {
			return bad("local needs -service")
		}
		lctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		entries, err := connectphone.Discover(lctx, *service)
		if err != nil {
			return fail(err)
		}
		addr := ""
		for e := range entries {
			if *name == "" || e.Instance == *name {
				fmt.Fprintf(stderr, "found %q\n", e.Instance)
				addr = e.Addr()
				break
			}
		}
		if addr == "" {
			return fail(errors.New("no host found"))
		}
		inv, err := connectphone.PairLocal(lctx, addr, connectphone.LocalOptions{Label: *label, Device: *device,
			OnCode: func(code string) { fmt.Fprintf(stderr, "code: %s (check that the computer shows the same)\n", code) }})
		if err != nil {
			return fail(err)
		}
		return finish(ctx, inv, *keyFile, *outFile, opts, stdout, stderr)
	case "connect", "dial":
		if *linkFile == "" {
			return bad(args[0] + " needs -link")
		}
		b, err := os.ReadFile(*linkFile)
		if err != nil {
			return fail(err)
		}
		link, err := connectphone.ParseLink(strings.TrimSpace(string(b)))
		if err != nil {
			return fail(err)
		}
		s, err := connectphone.Connect(link, opts)
		if err != nil {
			return fail(err)
		}
		defer s.Close()
		if args[0] == "dial" {
			dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			c, err := s.Dial(dctx)
			cancel()
			if err != nil {
				return fail(err)
			}
			defer c.Close()
			go func() { _, _ = io.Copy(c, stdin); closeWrite(c) }()
			_, _ = io.Copy(stdout, c)
			return 0
		}
		f, err := s.Forward()
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		fmt.Fprintf(stdout, "listening %s\n", f.Addr())
		<-ctx.Done()
		return 0
	}
	return bad("unknown command " + args[0])
}

func finish(ctx context.Context, inv connectinvite.Invite, keyFile, outFile string, opts connectphone.Options, stdout, stderr io.Writer) int {
	key, err := loadKey(keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	link, err := connectphone.Pair(pctx, inv, key, opts)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	text, _ := link.Encode()
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(text+"\n"), 0o600); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fmt.Fprintf(stderr, "paired with %q\n", link.Name)
		return 0
	}
	fmt.Fprintln(stdout, text)
	return 0
}

func loadKey(path string) (string, error) {
	if path == "" {
		return connectphone.NewKey(), nil
	}
	if b, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(b))
		if _, err := connectphone.PublicKey(key); err != nil {
			return "", err
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	key := connectphone.NewKey()
	return key, os.WriteFile(path, []byte(key+"\n"), 0o600)
}

func hostnameOr(fallback string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return fallback
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
