package gost

import (
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestSocksSimpleProxy exercises the standalone socksSimple Listener+Handler
// against a Client built from socksSimpleConnector+Transporter.
func TestSocksSimpleProxy(t *testing.T) {
	// Origin HTTP server.
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	user := url.UserPassword("alice", "secret")

	// Server side.
	ln, err := SocksSimpleListener("127.0.0.1:0", user)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &Server{Listener: ln}
	go srv.Serve(SocksSimpleHandler(user))
	defer srv.Close()

	// Client side.
	client := &Client{
		Connector:   SocksSimpleConnector(user),
		Transporter: SocksSimpleTransporter(user),
	}

	if err := proxyRoundtrip(client, srv, httpSrv.URL, []byte("ping")); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
}

// TestSocksSimpleAuthMismatchFails verifies that the XOR key derived from
// a wrong password yields a garbled stream that the server rejects.
func TestSocksSimpleAuthMismatchFails(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	srvUser := url.UserPassword("alice", "right-key")
	cliUser := url.UserPassword("alice", "wrong-key")

	ln, err := SocksSimpleListener("127.0.0.1:0", srvUser)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &Server{Listener: ln}
	go srv.Serve(SocksSimpleHandler(srvUser))
	defer srv.Close()

	client := &Client{
		Connector:   SocksSimpleConnector(cliUser),
		Transporter: SocksSimpleTransporter(cliUser),
	}

	// proxyRoundtrip should fail because the XOR streams disagree, so the
	// server can't decode the CONNECT frame's magic.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := proxyRoundtrip(client, srv, httpSrv.URL, []byte("ping")); err != nil {
			return // expected failure
		}
	}
	t.Fatal("expected roundtrip to fail with mismatched key")
}
