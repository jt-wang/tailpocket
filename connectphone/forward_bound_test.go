package connectphone

import (
	"io"
	"net"
	"testing"
	"time"
)

// The Tailcat route, measured (v0.3.5): a link whose Tailcat address answers nothing (a made-up DERP
// host) ends the app's request after 10 s, Tailcat's own limit for reaching the computer (tailcat
// v0.6.0 Client.ping), before Session.Forward's 20 s, and leaves no-answer. A network that blocks
// Tailcat looks the same to the phone.
func TestForwardEndsATailcatDialThatNeverAnswers(t *testing.T) {
	t.Parallel()
	s, err := Connect(Link{Address: testAddress(t), Port: 48931, Name: "Mac", Key: NewKey()}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f, err := s.Forward()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := io.WriteString(c, "GET "+f.BasePath()+"/ HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, err = io.ReadAll(c)
	took := time.Since(start)
	t.Logf("the forward closed the app's connection after %s", took.Round(100*time.Millisecond))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the request hung for 60 s")
	}
	if took < 9*time.Second || took > 12*time.Second {
		t.Fatalf("ended after %s, want about 10 s", took)
	}
	if f, ok := s.LastFailure(); !ok || f.Reason != ReasonNoAnswer || len(f.Routes) != 1 || f.Routes[0] != (RouteFailure{Route: "tailcat", Reason: ReasonNoAnswer}) {
		t.Fatalf("LastFailure %+v %v, want no-answer on tailcat", f, ok)
	}
}
