package connecthost

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/jt-wang/tailpocket/connectlocal"
	"github.com/jt-wang/tailpocket/connectmdns"
)

type netConn = net.Conn

// LocalOptions configures same-Wi-Fi pairing for one window.
type LocalOptions struct {
	// Service is the Bonjour type phones browse for, e.g. "_myapp._tcp". Required; on iOS the app
	// must also list it under NSBonjourServices.
	Service string
	// Label must match the phone's (default connectlocal.DefaultLabel).
	Label string
	// Instance is the name phones list (default: the host's Name).
	Instance string
	// Confirm shows the 6-digit code and device name and returns the user's decision. Required.
	Confirm func(ctx context.Context, code, device string) bool
	// Bindings and Advertise replace the LAN addresses and the Bonjour advertiser (tests, custom stacks).
	Bindings  []connectlocal.Binding
	Advertise func(connectmdns.Service) (stop func(), err error)
}

// ErrLocalUsed: ServeLocal was already called on this pairing window. Each window gets one, so its
// connectlocal.MaxAttempts bound the guesses for the whole window; open a new window to try again.
var ErrLocalUsed = errors.New("connecthost: ServeLocal runs once per pairing window; open a new one")

// ServeLocal advertises the window over Bonjour and hands the invite, sealed, to the first phone
// the user approves. It returns nil once delivered; the phone then joins with Wait as usual. It runs
// once per window (ErrLocalUsed after that). On connectlocal.ErrTooManyAttempts it also ends the
// window, so its QR code pairs nobody either: ask the user to start again.
func (p *Pairing) ServeLocal(ctx context.Context, opts LocalOptions) error {
	if !connectmdns.ValidType(opts.Service) {
		return errors.New("connecthost: LocalOptions.Service must look like _name._tcp")
	}
	if opts.Confirm == nil {
		return errors.New("connecthost: LocalOptions.Confirm is required")
	}
	label := opts.Label
	if label == "" {
		label = connectlocal.DefaultLabel
	}
	instance := connectmdns.CleanInstance(opts.Instance)
	if instance == "" {
		instance = connectmdns.CleanInstance(p.h.name)
	}
	if instance == "" {
		instance = "Computer"
	}
	advertise := opts.Advertise
	if advertise == nil {
		advertise = connectmdns.Advertise
	}
	p.mu.Lock()
	used := p.local
	p.local = true
	p.mu.Unlock()
	if used {
		return ErrLocalUsed
	}
	p.openV1() // the phone joins with the v1 invite it gets here (/pair; Confirm runs again, without emoji)
	plaintext, err := json.Marshal(p.inv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-p.ended:
			cancel()
		case <-ctx.Done():
		}
	}()
	var stop func()
	var advErr error
	err = connectlocal.Serve(ctx, connectlocal.HostOptions{Label: label, Plaintext: plaintext, Expires: p.expires, Confirm: opts.Confirm,
		Bindings: opts.Bindings, OnListening: func(port int) {
			stop, advErr = advertise(connectmdns.Service{Instance: instance, Type: opts.Service, Port: port, TXT: []string{"v=2"}})
			if advErr != nil {
				cancel()
			}
		}})
	if stop != nil {
		stop()
	}
	if advErr != nil {
		return advErr
	}
	if errors.Is(err, connectlocal.ErrTooManyAttempts) {
		p.Close()
	}
	return err
}
