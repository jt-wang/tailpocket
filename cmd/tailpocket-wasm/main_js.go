//go:build js && wasm

// tailpocket-wasm is the phone SDK for browsers and PWAs. It sets globalThis.tailPocketNative, which
// sdk/web/index.js wraps. Browsers have no raw UDP, so traffic always goes through the relays
// (over WebSockets), and there is no same-Wi-Fi discovery: pair by QR code or link.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall/js"
	"time"

	"github.com/jt-wang/tailpocket/connectinvite"
	"github.com/jt-wang/tailpocket/connectphone"
)

func main() {
	api := js.Global().Get("Object").New()
	api.Set("newKey", js.FuncOf(func(js.Value, []js.Value) any { return connectphone.NewKey() }))
	api.Set("publicKey", js.FuncOf(func(_ js.Value, a []js.Value) any {
		p, err := connectphone.PublicKey(arg(a, 0))
		if err != nil {
			return ""
		}
		return p
	}))
	api.Set("decodeInvite", js.FuncOf(func(_ js.Value, a []js.Value) any {
		prefix := arg(a, 1)
		if prefix == "" {
			prefix = connectinvite.DefaultPrefix
		}
		inv, err := connectinvite.Decode(arg(a, 0), prefix)
		if err != nil {
			return failure("invalid-invite")
		}
		b, _ := json.Marshal(inv)
		return string(b)
	}))
	api.Set("pair", js.FuncOf(pair))
	api.Set("request", js.FuncOf(request))
	api.Set("dial", js.FuncOf(dial))
	stop := make(chan struct{})
	var once sync.Once
	api.Set("exit", js.FuncOf(func(js.Value, []js.Value) any { once.Do(func() { close(stop) }); return nil }))
	js.Global().Set("tailPocketNative", api)
	if f := js.Global().Get("onTailPocketReady"); f.Type() == js.TypeFunction {
		f.Invoke()
	}
	<-stop
	sessionsMu.Lock()
	for _, s := range sessions {
		_ = s.Close()
	}
	sessionsMu.Unlock()
	// WebSocket close events arrive after Close returns; let them land before the runtime exits.
	time.Sleep(time.Second)
}

func arg(a []js.Value, i int) string {
	if i < len(a) && a[i].Type() == js.TypeString {
		return a[i].String()
	}
	return ""
}

func failure(code string) string { return `{"error":"` + code + `"}` }

func code(err error) string {
	switch {
	case errors.Is(err, connectphone.ErrExpired):
		return "expired"
	case errors.Is(err, connectphone.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, connectphone.ErrTaken):
		return "taken"
	case errors.Is(err, connectphone.ErrUnreachable):
		return "unreachable"
	case errors.Is(err, connectinvite.ErrInvalid):
		return "invalid-invite"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "failed"
}

// promise runs fn in a goroutine (blocking calls must not block the JS event loop).
func promise(fn func() (any, error)) js.Value {
	return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, a []js.Value) any {
		resolve, reject := a[0], a[1]
		go func() {
			v, err := fn()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(v)
		}()
		return nil
	}))
}

type codeError string

func (c codeError) Error() string { return string(c) }

// pair(inviteJSON, phoneKey, device, timeoutMs) → Promise<linkJSON>
func pair(_ js.Value, a []js.Value) any {
	inviteJSON, key, device := arg(a, 0), arg(a, 1), arg(a, 2)
	timeout := 90 * time.Second
	if len(a) > 3 && a[3].Type() == js.TypeNumber && a[3].Int() > 0 {
		timeout = time.Duration(a[3].Int()) * time.Millisecond
	}
	return promise(func() (any, error) {
		inv, err := connectinvite.ParseJSON([]byte(inviteJSON))
		if err != nil {
			return nil, codeError("invalid-invite")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		link, err := connectphone.Pair(ctx, inv, key, connectphone.Options{Device: device})
		if err != nil {
			return nil, codeError(code(err))
		}
		text, err := link.Encode()
		if err != nil {
			return nil, codeError("failed")
		}
		return text, nil
	})
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*connectphone.Session{}
)

func session(linkJSON string) (*connectphone.Session, error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if s := sessions[linkJSON]; s != nil {
		return s, nil
	}
	link, err := connectphone.ParseLink(linkJSON)
	if err != nil {
		return nil, codeError("invalid-link")
	}
	s, err := connectphone.Connect(link, connectphone.Options{})
	if err != nil {
		return nil, codeError("invalid-link")
	}
	sessions[linkJSON] = s
	return s, nil
}

func httpClient(s *connectphone.Session) *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return s.Dial(ctx) },
	}}
}

func bytesOf(v js.Value) []byte {
	switch v.Type() {
	case js.TypeString:
		return []byte(v.String())
	case js.TypeObject:
		if v.InstanceOf(js.Global().Get("Uint8Array")) {
			b := make([]byte, v.Get("length").Int())
			js.CopyBytesToGo(b, v)
			return b
		}
	}
	return nil
}

func uint8Array(b []byte) js.Value {
	out := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(out, b)
	return out
}

// request(linkJSON, {method, path, headers, body}) → Promise<{status, headers, body: Uint8Array}>
func request(_ js.Value, a []js.Value) any {
	linkJSON := arg(a, 0)
	opts := js.Undefined()
	if len(a) > 1 {
		opts = a[1]
	}
	get := func(k string) js.Value {
		if opts.Type() != js.TypeObject {
			return js.Undefined()
		}
		return opts.Get(k)
	}
	method, path := "GET", "/"
	if m := get("method"); m.Type() == js.TypeString {
		method = m.String()
	}
	if p := get("path"); p.Type() == js.TypeString {
		path = p.String()
	}
	headers := http.Header{}
	if h := get("headers"); h.Type() == js.TypeObject {
		keys := js.Global().Get("Object").Call("keys", h)
		for i := 0; i < keys.Length(); i++ {
			k := keys.Index(i).String()
			headers.Set(k, h.Get(k).String())
		}
	}
	body := bytesOf(get("body"))
	return promise(func() (any, error) {
		s, err := session(linkJSON)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(method, "http://host.invalid"+path, bytes.NewReader(body))
		if err != nil {
			return nil, codeError("invalid-request")
		}
		req.Header = headers
		var resp *http.Response
		for attempt := 0; attempt < 4; attempt++ { // the first dial may race the relay handshake
			if resp, err = httpClient(s).Do(req); err == nil {
				break
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		if err != nil {
			return nil, codeError("unreachable")
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, codeError("failed")
		}
		out := js.Global().Get("Object").New()
		out.Set("status", resp.StatusCode)
		hdrs := js.Global().Get("Object").New()
		for k, v := range resp.Header {
			if len(v) > 0 {
				hdrs.Set(k, v[0])
			}
		}
		out.Set("headers", hdrs)
		out.Set("body", uint8Array(data))
		return out, nil
	})
}

// dial(linkJSON) → Promise<{read(): Promise<Uint8Array|null>, write(bytes): Promise<void>, close()}>
func dial(_ js.Value, a []js.Value) any {
	linkJSON := arg(a, 0)
	return promise(func() (any, error) {
		s, err := session(linkJSON)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := s.Dial(ctx)
		if err != nil {
			return nil, codeError("unreachable")
		}
		obj := js.Global().Get("Object").New()
		obj.Set("read", js.FuncOf(func(js.Value, []js.Value) any {
			return promise(func() (any, error) {
				buf := make([]byte, 32*1024)
				n, err := conn.Read(buf)
				if n > 0 {
					return uint8Array(buf[:n]), nil
				}
				if err == io.EOF {
					return js.Null(), nil
				}
				return nil, codeError("closed")
			})
		}))
		obj.Set("write", js.FuncOf(func(_ js.Value, w []js.Value) any {
			var data []byte
			if len(w) > 0 {
				data = bytesOf(w[0])
			}
			return promise(func() (any, error) {
				if _, err := conn.Write(data); err != nil {
					return nil, codeError("closed")
				}
				return js.Undefined(), nil
			})
		}))
		obj.Set("close", js.FuncOf(func(js.Value, []js.Value) any { _ = conn.Close(); return nil }))
		return obj, nil
	})
}
