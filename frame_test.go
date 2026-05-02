package gost

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []*Frame{
		{Type: FrameTypeAdmin, Cmd: AdminCmdPing, StreamID: 0, Payload: nil},
		{Type: FrameTypeXOR, Cmd: XORCmdData, StreamID: 42, Payload: []byte("hello")},
		{Type: FrameTypeXOR, Cmd: XORCmdData, StreamID: 0xFFFFFFFF, Payload: bytes.Repeat([]byte{0xAB}, FrameMaxPayload)},
	}
	for i, in := range cases {
		var buf bytes.Buffer
		if err := in.EncodeTo(&buf); err != nil {
			t.Fatalf("case %d: encode: %v", i, err)
		}
		out, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if out.Type != in.Type || out.Cmd != in.Cmd || out.StreamID != in.StreamID {
			t.Fatalf("case %d: header mismatch got=%+v want=%+v", i, out, in)
		}
		if !bytes.Equal(out.Payload, in.Payload) {
			t.Fatalf("case %d: payload mismatch", i)
		}
	}
}

func TestFramePayloadTooLarge(t *testing.T) {
	f := &Frame{Type: FrameTypeXOR, Payload: make([]byte, FrameMaxPayload+1)}
	if err := f.EncodeTo(&bytes.Buffer{}); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("want ErrPayloadTooLarge, got %v", err)
	}
}

func TestFrameBadMagic(t *testing.T) {
	bad := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := ReadFrame(bytes.NewReader(bad))
	if !errors.Is(err, ErrBadMagic) {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

func TestFrameShortRead(t *testing.T) {
	// only header for a frame that claims 10 bytes payload, but truncated.
	var buf bytes.Buffer
	(&Frame{Type: FrameTypeXOR, Payload: []byte("0123456789")}).EncodeTo(&buf)
	truncated := buf.Bytes()[:FrameHeaderSize+5]
	_, err := ReadFrame(bytes.NewReader(truncated))
	if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want unexpected EOF, got %v", err)
	}
}

func TestTLVRoundTrip(t *testing.T) {
	payload, err := EncodeTLVs(
		TLVUint32(TLVStreamID, 0x01020304),
		TLVUint16(TLVDataPort, 1023),
		TLVString(TLVProto, "socks5"),
		TLVString(TLVSrcAddr, "10.0.0.1:1234"),
		TLVBytes(TLVXORKey, []byte("k\x00ey")),
	)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	m, err := DecodeTLVs(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := LookupUint32(m, TLVStreamID); got != 0x01020304 {
		t.Fatalf("stream id: %x", got)
	}
	if got := LookupUint16(m, TLVDataPort); got != 1023 {
		t.Fatalf("data port: %d", got)
	}
	if got := LookupString(m, TLVProto); got != "socks5" {
		t.Fatalf("proto: %q", got)
	}
	if got := LookupString(m, TLVSrcAddr); got != "10.0.0.1:1234" {
		t.Fatalf("src addr: %q", got)
	}
	if got, want := m[TLVXORKey], []byte("k\x00ey"); !bytes.Equal(got, want) {
		t.Fatalf("xor key: %x", got)
	}
}

func TestTLVTruncated(t *testing.T) {
	// claims length 5 but only 2 bytes of value present
	bad := []byte{TLVProto, 0x00, 0x05, 'a', 'b'}
	if _, err := DecodeTLVs(bad); err == nil {
		t.Fatalf("want error for truncated TLV")
	}
}
