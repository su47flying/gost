package gost

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNoportEndToEnd brings up a real B-side admin+data listener, an
// A-side AdminClient, and a B-side user-facing HTTP listener bridged
// through the hub. It then issues an HTTP GET via the bridge and
// confirms the reply originates at A's exit (the test HTTP server).
func TestNoportEndToEnd(t *testing.T) {
	// 1) target HTTP server (acts as A's exit destination)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello-from-target"))
	}))
	defer target.Close()

	// 2) B side: pick free ports for admin + data-queue.
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dqLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	userLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer adminLn.Close()
	defer dqLn.Close()
	defer userLn.Close()

	user := "u1"
	authKey := []byte("authsecret")

	// admin accept loop
	adminH := &adminHandler{user: user, key: authKey, opts: HubOptions{PoolSize: 2, BigflowKBps: 1024, BigflowSeconds: 5, IdleTimeout: 30 * time.Second}}
	adminH.Init()
	go func() {
		c, err := adminLn.Accept()
		if err != nil {
			return
		}
		adminH.Handle(c)
	}()

	// data-queue accept loop (allow several queues)
	dqH := &dataQueueHandler{user: user}
	dqH.Init()
	go func() {
		for {
			c, err := dqLn.Accept()
			if err != nil {
				return
			}
			go dqH.Handle(c)
		}
	}()

	// 3) A side: admin client; HandlerFor injects a custom HTTP-direct
	// handler so we don't need to spin a full SOCKS stack.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &AdminClient{
		BAddr:    adminLn.Addr().String(),
		DataAddr: dqLn.Addr().String(),
		User:     user,
		AuthKey:  authKey,
		PoolSize: 2,
		HandlerFor: func(proto string, _ Handler) Handler {
			return testDirectHandler{target: target.Listener.Addr().String()}
		},
	}
	go c.Run(ctx)

	// 4) wait for hub registration + at least 1 pool queue.
	deadline := time.Now().Add(3 * time.Second)
	var hub *AdminHub
	for time.Now().Before(deadline) {
		hub = LookupHub(user)
		if hub != nil {
			hub.mu.Lock()
			n := len(hub.pool)
			hub.mu.Unlock()
			if n > 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hub == nil {
		t.Fatal("hub not registered")
	}

	// 5) B-side user listener: every accepted conn -> hub.OpenStream("auto", ...)
	bridge := &bridgeHandler{proto: "auto", xorKey: []byte("dataxor")}
	bridge.Init(AddrHandlerOption(userLn.Addr().String()))
	go func() {
		for {
			c, err := userLn.Accept()
			if err != nil {
				return
			}
			go bridge.Handle(c)
		}
	}()

	// 6) Connect a TCP client to userLn, send raw HTTP request, read response.
	conn, err := net.Dial("tcp", userLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET / HTTP/1.0\r\nHost: x\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !contains(resp, "hello-from-target") {
		t.Fatalf("unexpected response: %q", string(resp))
	}
}

func contains(haystack []byte, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h []byte, n string) int {
	if len(n) == 0 {
		return 0
	}
outer:
	for i := 0; i <= len(h)-len(n); i++ {
		for j := 0; j < len(n); j++ {
			if h[i+j] != n[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

// testDirectHandler is a trivial handler that opens a TCP connection to
// `target` and bidirectionally bridges it. It substitutes for a real
// socks5/http handler in TestNoportEndToEnd.
type testDirectHandler struct {
	target string
}

func (testDirectHandler) Init(_ ...HandlerOption) {}
func (h testDirectHandler) Handle(conn net.Conn) {
	defer conn.Close()
	dst, err := net.Dial("tcp", h.target)
	if err != nil {
		return
	}
	defer dst.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(dst, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, dst); done <- struct{}{} }()
	<-done
}
