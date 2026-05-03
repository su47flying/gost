package gost

import (
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestNoportSocks5ViaTunnel exercises the full A+B+C+target path:
//
//	C  --socks5-->  B (-L=socks5)  --[hub chain]-->  A (data-queue worker)  -->  origin
//	                       ^                              |
//	                       └──── A registered via -T=admin -> B (-R=admin)
//
// The test runs both A and B in-process. A connects to B using AdminClient.
// B exposes a socks5 listener whose Chain is the noport hub chain, so each
// outgoing socks5 dial goes through an idle data-queue conn previously
// opened by A.
func TestNoportSocks5ViaTunnel(t *testing.T) {
	user := url.UserPassword("noport-user", "noport-key")

	// Origin HTTP server (the real target Host A will dial).
	originSrv := httptest.NewServer(httpTestHandler)
	defer originSrv.Close()

	// ---- B side ----
	hub := NewAdminHub("", 4)

	// Data-queue listener on B.
	dataLn, err := SocksSimpleListener("127.0.0.1:0", user)
	if err != nil {
		t.Fatalf("data ln: %v", err)
	}
	dataSrv := &Server{Listener: dataLn}
	go dataSrv.Serve(SocksSimpleHandlerWithHubExported(user, hub,
		AddrHandlerOption(dataLn.Addr().String()),
		UsersHandlerOption(user),
	))
	defer dataSrv.Close()
	SetAdminHubDataAddr(hub, dataLn.Addr().String())

	// Admin listener on B.
	adminLn, err := AdminListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("admin ln: %v", err)
	}
	adminSrv := &Server{Listener: adminLn}
	go adminSrv.Serve(AdminHandler(user, hub,
		AddrHandlerOption(adminLn.Addr().String()),
		UsersHandlerOption(user),
	))
	defer adminSrv.Close()

	// User-facing socks5 listener on B, chained via the hub.
	socks5Ln, err := TCPListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 ln: %v", err)
	}
	socks5Srv := &Server{Listener: socks5Ln}
	socks5H := SOCKS5Handler(
		AddrHandlerOption(socks5Ln.Addr().String()),
		ChainHandlerOption(NewHubChain(hub)),
	)
	go socks5Srv.Serve(socks5H)
	defer socks5Srv.Close()

	// ---- A side ----
	a := NewAdminClient(adminLn.Addr().String(), user)
	a.Start()
	defer a.Close()

	// Wait until at least one HELLO'd data conn has been pushed into the hub.
	if !waitForCondition(2*time.Second, func() bool {
		s := hub.pickSession()
		if s == nil {
			return false
		}
		s.queueMu.Lock()
		n := len(s.queue)
		s.queueMu.Unlock()
		return n > 0
	}) {
		t.Fatal("timeout waiting for A to register and push data conns")
	}

	// ---- C side: socks5 client ----
	cClient := &Client{
		Connector:   SOCKS5Connector(nil),
		Transporter: TCPTransporter(),
	}

	if err := proxyRoundtrip(cClient, socks5Srv, originSrv.URL, []byte("hello via noport")); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}

	// Run another request to confirm the pool is being refilled.
	if err := proxyRoundtrip(cClient, socks5Srv, originSrv.URL, []byte("second request")); err != nil {
		t.Fatalf("second roundtrip: %v", err)
	}
}

// TestNoportDuplicateAuthRejected verifies that a second AdminClient using
// the same credentials is rejected (registration semantics).
func TestNoportDuplicateAuthRejected(t *testing.T) {
	user := url.UserPassword("u", "k")

	hub := NewAdminHub("127.0.0.1:1", 2)
	dataLn, _ := SocksSimpleListener("127.0.0.1:0", user)
	defer dataLn.Close()
	SetAdminHubDataAddr(hub, dataLn.Addr().String())

	adminLn, err := AdminListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("admin ln: %v", err)
	}
	srv := &Server{Listener: adminLn}
	go srv.Serve(AdminHandler(user, hub, UsersHandlerOption(user)))
	defer srv.Close()

	a1 := NewAdminClient(adminLn.Addr().String(), user)
	a1.Start()
	defer a1.Close()

	if !waitForCondition(2*time.Second, func() bool {
		return hub.SessionCount() == 1
	}) {
		t.Fatal("first session never registered")
	}

	a2 := NewAdminClient(adminLn.Addr().String(), user)
	a2.Start()
	defer a2.Close()

	// SessionCount must stay at 1 even after a brief settle window.
	time.Sleep(500 * time.Millisecond)
	if got := hub.SessionCount(); got != 1 {
		t.Fatalf("expected SessionCount=1 (duplicate rejected), got %d", got)
	}
}

func waitForCondition(d time.Duration, pred func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pred() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return pred()
}

func TestResolveDataAddrWildcard(t *testing.T) {
	c := &AdminClient{addr: "1.2.3.4:36962"}
	cases := map[string]string{
		"[::]:36963":    "1.2.3.4:36963",
		"0.0.0.0:36963": "1.2.3.4:36963",
		":36963":        "1.2.3.4:36963",
		"5.6.7.8:36963": "5.6.7.8:36963",
	}
	for in, want := range cases {
		if got := c.resolveDataAddr(in); got != want {
			t.Errorf("resolveDataAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
