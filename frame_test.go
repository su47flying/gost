package gost

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestFrameRoundtrip(t *testing.T) {
	cases := []Frame{
		{Type: FrameTypeAdmin, Cmd: AdminCmdAuth, Payload: []byte("alice:secret")},
		{Type: FrameTypeAdmin, Cmd: AdminCmdAuthOK},
		{Type: FrameTypeData, Cmd: DataCmdConnect, Payload: []byte("tcp 127.0.0.1:80")},
		{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte("ok")},
	}
	var buf bytes.Buffer
	for _, f := range cases {
		buf.Reset()
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame %v: %v", f, err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if got.Type != f.Type || got.Cmd != f.Cmd || !bytes.Equal(got.Payload, f.Payload) {
			t.Fatalf("frame mismatch: got=%+v want=%+v", got, f)
		}
	}
}

func TestFrameBadMagic(t *testing.T) {
	bad := []byte{0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0}
	if _, err := ReadFrame(bytes.NewReader(bad)); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestFramePayloadTooLarge(t *testing.T) {
	f := Frame{Type: FrameTypeData, Cmd: DataCmdConnect, Payload: make([]byte, FrameMaxPayload+1)}
	if err := WriteFrame(&bytes.Buffer{}, f); err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

// pipeConn wraps net.Pipe with a pair of XOR-encrypted ends sharing key.
func xorPipe(key []byte) (net.Conn, net.Conn) {
	a, b := net.Pipe()
	return NewXORConn(a, key), NewXORConn(b, key)
}

func TestXORConnEcho(t *testing.T) {
	a, b := xorPipe([]byte("k3y"))
	defer a.Close()
	defer b.Close()

	go func() {
		buf := make([]byte, 64)
		n, _ := b.Read(buf)
		_, _ = b.Write(buf[:n])
	}()

	want := []byte("hello, noport!")
	if _, err := a.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	a.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := a.(*xorConn).Conn.Read(make([]byte, 0)); err != nil {
		// triggers nothing, we just want the conn pointer; reset deadline below
	}
	a.SetReadDeadline(time.Time{})
	if _, err := readFull(a, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got=%q want=%q", got, want)
	}
}

func readFull(c net.Conn, p []byte) (int, error) {
	read := 0
	for read < len(p) {
		n, err := c.Read(p[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func TestXORConnEncryptsBytes(t *testing.T) {
	// Bytes on the underlying pipe must NOT equal the plaintext.
	raw1, raw2 := net.Pipe()
	defer raw1.Close()
	defer raw2.Close()
	enc := NewXORConn(raw1, []byte("abc"))

	plain := []byte("PLAINTEXT")
	go func() { enc.Write(plain) }()
	got := make([]byte, len(plain))
	if _, err := readFull(raw2, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Equal(got, plain) {
		t.Fatalf("bytes were not encrypted: %q", got)
	}
}

func TestFrameOverXORConn(t *testing.T) {
	a, b := xorPipe([]byte("password"))
	defer a.Close()
	defer b.Close()

	want := Frame{Type: FrameTypeData, Cmd: DataCmdHello, Payload: []byte("u:p")}
	go func() { WriteFrame(a, want) }()
	got, err := ReadFrame(b)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Type != want.Type || got.Cmd != want.Cmd || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("frame mismatch: got=%+v want=%+v", got, want)
	}
}
