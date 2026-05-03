package gost

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Frame protocol used by the noport (admin / socksSimple) channels.
//
// On-wire header layout (12 bytes, big endian):
//
//	magic    uint32  // FrameMagic
//	type     uint8   // FrameTypeAdmin or FrameTypeData
//	cmd      uint8   // command id, namespace depends on type
//	reserved uint16  // 0
//	length   uint32  // payload length in bytes (may be 0)
//	payload  [length]byte
//
// The full TCP stream (header + payload, in both directions) is XOR
// encrypted by xorConn using the shared password as the key. Once a
// data-queue connection is in the "tunneled" phase (after a successful
// CONNECT_ACK), no more frames are exchanged: raw bytes are forwarded
// in both directions, still XOR encrypted by xorConn.
const (
	FrameMagic      uint32 = 0x00003193
	FrameHeaderSize        = 12
	FrameMaxPayload        = 1 << 24 // 16 MiB hard cap
)

// Frame types.
const (
	FrameTypeAdmin uint8 = 1
	FrameTypeData  uint8 = 2
)

// Admin commands (FrameTypeAdmin).
const (
	AdminCmdAuth      uint8 = 1
	AdminCmdAuthOK    uint8 = 2
	AdminCmdAuthFail  uint8 = 3
	AdminCmdOpenQueue uint8 = 4
	AdminCmdPing      uint8 = 5
	AdminCmdPong      uint8 = 6
)

// Data-queue commands (FrameTypeData) — used during the control phase.
const (
	DataCmdHello      uint8 = 1
	DataCmdConnect    uint8 = 2
	DataCmdConnectAck uint8 = 3
)

// ErrBadFrame is returned when a frame fails to decode (bad magic / oversize).
var ErrBadFrame = errors.New("noport: bad frame")

// Frame is a single message exchanged on an admin or data-queue connection.
type Frame struct {
	Type    uint8
	Cmd     uint8
	Payload []byte
}

// WriteFrame writes f to w using the noport frame format.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > FrameMaxPayload {
		return fmt.Errorf("noport: payload too large: %d", len(f.Payload))
	}
	buf := make([]byte, FrameHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], FrameMagic)
	buf[4] = f.Type
	buf[5] = f.Cmd
	binary.BigEndian.PutUint16(buf[6:8], 0)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(f.Payload)))
	copy(buf[FrameHeaderSize:], f.Payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads a single frame from r.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if magic := binary.BigEndian.Uint32(hdr[0:4]); magic != FrameMagic {
		return Frame{}, fmt.Errorf("%w: magic=%#x", ErrBadFrame, magic)
	}
	f := Frame{Type: hdr[4], Cmd: hdr[5]}
	n := binary.BigEndian.Uint32(hdr[8:12])
	if n > FrameMaxPayload {
		return Frame{}, fmt.Errorf("%w: payload size %d > max %d", ErrBadFrame, n, FrameMaxPayload)
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// xorConn wraps a net.Conn and XOR encrypts all bytes in both
// directions using a repeating key. Read offset and write offset are
// tracked independently so peers stay in sync regardless of read/write
// interleaving.
type xorConn struct {
	net.Conn
	key      []byte
	readOff  uint64
	writeOff uint64
	readMu   sync.Mutex
	writeMu  sync.Mutex
}

// NewXORConn wraps c with stream XOR encryption keyed by key.
// If key is empty the connection is returned unchanged (no encryption).
func NewXORConn(c net.Conn, key []byte) net.Conn {
	if len(key) == 0 {
		return c
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &xorConn{Conn: c, key: k}
}

func (c *xorConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.readMu.Lock()
		off := c.readOff
		k := c.key
		klen := uint64(len(k))
		for i := 0; i < n; i++ {
			p[i] ^= k[(off+uint64(i))%klen]
		}
		c.readOff = off + uint64(n)
		c.readMu.Unlock()
	}
	return n, err
}

func (c *xorConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return c.Conn.Write(p)
	}
	c.writeMu.Lock()
	buf := make([]byte, len(p))
	off := c.writeOff
	k := c.key
	klen := uint64(len(k))
	for i := 0; i < len(p); i++ {
		buf[i] = p[i] ^ k[(off+uint64(i))%klen]
	}
	c.writeOff = off + uint64(len(p))
	c.writeMu.Unlock()
	n, err := c.Conn.Write(buf)
	// On a partial write, the peer's read offset only advanced by n,
	// but our writeOff has already moved by len(p). To keep both sides
	// in sync we treat partial writes as fatal by returning an error.
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// SetIdleTimeout is a helper used by long-running noport connections.
// It sets both read and write deadlines if the underlying conn supports it.
func setIdleDeadline(c net.Conn, d time.Duration) {
	if d <= 0 {
		return
	}
	_ = c.SetDeadline(time.Now().Add(d))
}
