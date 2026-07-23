package gost

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
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

// TestNoportPoolSelfHealsAfterIdleDeath verifies that the data-queue pool
// on Host A rebuilds itself after its idle conns die, without any user
// traffic to nudge a refill. This is the regression test for the bug where
// gost could no longer create new connections after running for a while:
// idle pool conns die over time (NAT/keepalive/network blip) and, before
// the fix, A's slot goroutines exited without replacing them, draining the
// pool to zero so B's Acquire could never hand out a tunnel again.
func TestNoportPoolSelfHealsAfterIdleDeath(t *testing.T) {
	user := url.UserPassword("u", "k")
	const poolSize = 4
	hub := NewAdminHub("", poolSize)

	dataLn, err := SocksSimpleListener("127.0.0.1:0", user)
	if err != nil {
		t.Fatal(err)
	}
	dataSrv := &Server{Listener: dataLn}
	go dataSrv.Serve(SocksSimpleHandlerWithHubExported(user, hub,
		AddrHandlerOption(dataLn.Addr().String()), UsersHandlerOption(user)))
	defer dataSrv.Close()
	SetAdminHubDataAddr(hub, dataLn.Addr().String())

	adminLn, err := AdminListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminSrv := &Server{Listener: adminLn}
	go adminSrv.Serve(AdminHandler(user, hub,
		AddrHandlerOption(adminLn.Addr().String()), UsersHandlerOption(user)))
	defer adminSrv.Close()

	a := NewAdminClient(adminLn.Addr().String(), user)
	a.Start()
	defer a.Close()

	poolLen := func() int {
		s := hub.pickSession()
		if s == nil {
			return 0
		}
		s.queueMu.Lock()
		defer s.queueMu.Unlock()
		return len(s.queue)
	}

	// Wait for the pool to fill initially.
	if !waitForCondition(3*time.Second, func() bool { return poolLen() >= poolSize }) {
		t.Fatalf("pool never filled to %d (got %d)", poolSize, poolLen())
	}

	// Simulate every idle conn dying at once (as a network blip or B restart
	// would): close them on the B side and drop them from the queue.
	s := hub.pickSession()
	s.queueMu.Lock()
	dead := s.queue
	s.queue = nil
	s.queueMu.Unlock()
	for _, c := range dead {
		_ = c.Close()
	}
	if got := poolLen(); got != 0 {
		t.Fatalf("expected pool drained to 0 after kill, got %d", got)
	}

	// With no user traffic to trigger a refill, the pool must climb back to
	// poolSize entirely on its own.
	if !waitForCondition(6*time.Second, func() bool { return poolLen() >= poolSize }) {
		t.Fatalf("pool did not self-heal: got %d, want >= %d", poolLen(), poolSize)
	}

	// And it must not grow without bound: the slots are fixed at poolSize, so
	// after settling the pool should hold roughly poolSize conns, never a
	// runaway multiple of it (regression guard for OPEN_QUEUE stacking).
	time.Sleep(500 * time.Millisecond)
	if got := poolLen(); got > poolSize*2 {
		t.Fatalf("pool grew unbounded: got %d, want ~%d", got, poolSize)
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

// TestNoportConcurrentLargeStream simulates a YouTube-app-like load:
// many parallel HTTP requests through the SOCKS5/hub chain, each
// downloading a sizable body. Verifies data integrity and that the
// pool refill keeps up under burst.
func TestNoportConcurrentLargeStream(t *testing.T) {
	user := url.UserPassword("u", "k")

	const chunk = 256 * 1024 // 256 KiB per response
	payload := make([]byte, chunk)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.Write(payload)
	}))
	defer originSrv.Close()

	hub := NewAdminHub("", 4) // small pool to force refill

	dataLn, err := SocksSimpleListener("127.0.0.1:0", user)
	if err != nil {
		t.Fatal(err)
	}
	dataSrv := &Server{Listener: dataLn}
	go dataSrv.Serve(SocksSimpleHandlerWithHubExported(user, hub,
		AddrHandlerOption(dataLn.Addr().String()), UsersHandlerOption(user)))
	defer dataSrv.Close()
	SetAdminHubDataAddr(hub, dataLn.Addr().String())

	adminLn, err := AdminListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminSrv := &Server{Listener: adminLn}
	go adminSrv.Serve(AdminHandler(user, hub,
		AddrHandlerOption(adminLn.Addr().String()), UsersHandlerOption(user)))
	defer adminSrv.Close()

	socks5Ln, err := TCPListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Srv := &Server{Listener: socks5Ln}
	go socks5Srv.Serve(SOCKS5Handler(
		AddrHandlerOption(socks5Ln.Addr().String()),
		ChainHandlerOption(NewHubChain(hub)),
	))
	defer socks5Srv.Close()

	a := NewAdminClient(adminLn.Addr().String(), user)
	a.Start()
	defer a.Close()

	if !waitForCondition(2*time.Second, func() bool {
		s := hub.pickSession()
		if s == nil {
			return false
		}
		s.queueMu.Lock()
		n := len(s.queue)
		s.queueMu.Unlock()
		return n >= 4
	}) {
		t.Fatal("pool never filled")
	}

	const concurrency = 16
	const perWorker = 3
	hash := sha256.Sum256(payload)
	wantHash := hash[:]

	socks5Addr, err := net.ResolveTCPAddr("tcp", socks5Ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := proxy.SOCKS5("tcp", socks5Addr.String(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Dial: dialer.Dial,
		// Disable connection reuse so each request goes through a fresh tunnel.
		DisableKeepAlives: true,
	}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	errCh := make(chan error, concurrency*perWorker)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				resp, err := hc.Get(originSrv.URL)
				if err != nil {
					errCh <- fmt.Errorf("worker %d req %d: %w", id, j, err)
					return
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					errCh <- fmt.Errorf("worker %d req %d read: %w", id, j, err)
					return
				}
				gotHash := sha256.Sum256(body)
				if !bytes.Equal(gotHash[:], wantHash) {
					errCh <- fmt.Errorf("worker %d req %d: payload mismatch (len=%d)", id, j, len(body))
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestNoportUDPAssociateRelay verifies that SOCKS5 UDP_ASSOCIATE through
// the noport hub chain correctly relays datagrams. Without this support
// QUIC-based clients (notably iOS YouTube App / Cronet) lose all video
// frames while non-QUIC apps continue to work.
func TestNoportUDPAssociateRelay(t *testing.T) {
	user := url.UserPassword("u", "k")
	hub := NewAdminHub("", 4)

	dataLn, err := SocksSimpleListener("127.0.0.1:0", user)
	if err != nil {
		t.Fatal(err)
	}
	dataSrv := &Server{Listener: dataLn}
	go dataSrv.Serve(SocksSimpleHandlerWithHubExported(user, hub,
		AddrHandlerOption(dataLn.Addr().String()), UsersHandlerOption(user)))
	defer dataSrv.Close()
	SetAdminHubDataAddr(hub, dataLn.Addr().String())

	adminLn, err := AdminListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminSrv := &Server{Listener: adminLn}
	go adminSrv.Serve(AdminHandler(user, hub,
		AddrHandlerOption(adminLn.Addr().String()), UsersHandlerOption(user)))
	defer adminSrv.Close()

	socks5Ln, err := TCPListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Srv := &Server{Listener: socks5Ln}
	go socks5Srv.Serve(SOCKS5Handler(
		AddrHandlerOption(socks5Ln.Addr().String()),
		ChainHandlerOption(NewHubChain(hub))))
	defer socks5Srv.Close()

	a := NewAdminClient(adminLn.Addr().String(), user)
	a.Start()
	defer a.Close()

	if !waitForCondition(2*time.Second, func() bool {
		return hub.SessionCount() > 0
	}) {
		t.Fatal("session never registered")
	}

	// Stand up an echo UDP server.
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			udpEcho.WriteTo(buf[:n], peer)
		}
	}()

	// Drive the SOCKS5 client manually so we can test UDP_ASSOCIATE.
	c, err := net.Dial("tcp", socks5Ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Greeting (no auth): 05 01 00
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greeting reply: %v", resp)
	}
	// UDP_ASSOCIATE request: VER=5 CMD=3 RSV=0 ATYP=1 0.0.0.0 :0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("UDP_ASSOCIATE reply header read failed: %v", err)
	}
	if hdr[0] != 0x05 {
		t.Fatalf("bad reply ver=%x", hdr[0])
	}
	if hdr[1] != 0x00 {
		t.Fatalf("UDP_ASSOCIATE failed (rep=%d) — UDP relay broken", hdr[1])
	}
	// Read the rest of reply (BND.ADDR + BND.PORT)
	rest := make([]byte, 4+2) // IPv4 + port
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("read bnd: %v", err)
	}
	bndIP := net.IPv4(rest[0], rest[1], rest[2], rest[3])
	bndPort := int(rest[4])<<8 | int(rest[5])
	if bndIP.IsUnspecified() {
		bndIP = net.ParseIP("127.0.0.1")
	}
	bnd := &net.UDPAddr{IP: bndIP, Port: bndPort}
	t.Logf("UDP_ASSOCIATE replied success, BND=%s", bnd)

	udpClient, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()

	// SOCKS5 UDP datagram framing: RSV=0,0 FRAG=0 ATYP=1 IP4 PORT DATA
	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	pkt := []byte{0, 0, 0, 0x01, echoAddr.IP.To4()[0], echoAddr.IP.To4()[1], echoAddr.IP.To4()[2], echoAddr.IP.To4()[3]}
	pkt = append(pkt, byte(echoAddr.Port>>8), byte(echoAddr.Port))
	payload := []byte("ping-via-quic-style")
	pkt = append(pkt, payload...)

	if _, err := udpClient.WriteTo(pkt, bnd); err != nil {
		t.Fatal(err)
	}
	udpClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	rbuf := make([]byte, 2048)
	n, _, err := udpClient.ReadFrom(rbuf)
	if err != nil {
		t.Fatalf("UDP relay broken: did not receive echo back: %v", err)
	}
	// Reply is also SOCKS5-framed: skip 4-byte header + IP + port = 10
	if n < 10 || !bytes.Equal(rbuf[10:n], payload) {
		t.Fatalf("UDP echo mismatch: got %q want suffix %q", rbuf[:n], payload)
	}
	t.Logf("✓ UDP relay through noport chain works: echoed %d bytes", n-10)
}
