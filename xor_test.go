package gost

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

func TestXORConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	key := []byte("secret-xor-key-123")
	xa := newXORConn(a, key)
	xb := newXORConn(b, key)

	want := bytes.Repeat([]byte("hello world\n"), 5000) // ~60KB > one frame
	var got bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, err := xb.Read(buf)
			if n > 0 {
				got.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	if _, err := xa.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	xa.Close()
	wg.Wait()

	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", got.Len(), len(want))
	}
}

func TestXORConnWrongKey(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	xa := newXORConn(a, []byte("keyA"))
	xb := newXORConn(b, []byte("keyB"))
	go func() {
		xa.Write([]byte("hello"))
		xa.Close()
	}()
	buf := make([]byte, 64)
	n, err := xb.Read(buf)
	if err != nil && err != io.EOF {
		// allowed: framing succeeds but plaintext is garbled
	}
	if n > 0 && string(buf[:n]) == "hello" {
		t.Fatalf("decryption with wrong key should not yield plaintext")
	}
}
