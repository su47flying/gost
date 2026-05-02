package gost

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/go-log/log"
)

// xorMaxFrameData is the maximum decrypted bytes per frame written by xorConn.
// Kept well under FrameMaxPayload so headers + bursts always fit.
const xorMaxFrameData = 32 * 1024

// xorKeyOf returns the XOR key bytes for the given URL userinfo.
// In `XOR://user@key:host:port` the password ("key") is the encryption key.
// If the password is empty, the username itself is used as the key.
func xorKeyOf(u *url.Userinfo) []byte {
	if u == nil {
		return nil
	}
	if k, ok := u.Password(); ok && k != "" {
		return []byte(k)
	}
	return []byte(u.Username())
}

// xorMask XORs out=in with key starting at the given byte offset.
// Returns the new offset (offset+len(in)) for chaining.
func xorMask(out, in, key []byte, offset uint64) uint64 {
	if len(key) == 0 {
		copy(out, in)
		return offset + uint64(len(in))
	}
	for i, b := range in {
		out[i] = b ^ key[(offset+uint64(i))%uint64(len(key))]
	}
	return offset + uint64(len(in))
}

// xorConn wraps an underlying net.Conn with framed XOR encryption.
// It implements net.Conn. Reads/Writes deliver decrypted/plaintext data.
//
// streamID is embedded in every frame so the same wrapper type can also be
// used as one stream within a multiplexed data queue (see admin.go) — but
// when used standalone, streamID is simply 0.
type xorConn struct {
	conn      net.Conn
	br        *bufio.Reader // for Peek-style first-frame inspection (optional)
	key       []byte
	streamID  uint32
	writeSeq  uint64
	readSeq   uint64
	readBuf   []byte // leftover decrypted bytes
	mu        sync.Mutex
	closed    bool
	remoteRaw net.Addr
}

func newXORConn(c net.Conn, key []byte) *xorConn {
	return &xorConn{
		conn: c,
		br:   bufio.NewReader(c),
		key:  key,
	}
}

func (c *xorConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		f, err := ReadFrame(c.br)
		if err != nil {
			return 0, err
		}
		if f.Type != FrameTypeXOR {
			return 0, fmt.Errorf("xor: unexpected frame type %d", f.Type)
		}
		switch f.Cmd {
		case XORCmdData:
			if len(f.Payload) == 0 {
				continue
			}
			dec := make([]byte, len(f.Payload))
			c.readSeq = xorMask(dec, f.Payload, c.key, c.readSeq)
			n := copy(p, dec)
			if n < len(dec) {
				c.readBuf = dec[n:]
			}
			return n, nil
		case XORCmdStreamFin:
			return 0, io.EOF
		case XORCmdQueueHello:
			// QueueHello is a control frame that should be consumed by the
			// data queue layer, not by a regular xorConn user. Skip it
			// silently in case it leaks here.
			continue
		default:
			return 0, fmt.Errorf("xor: unknown cmd %d", f.Cmd)
		}
	}
}

func (c *xorConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > xorMaxFrameData {
			chunk = chunk[:xorMaxFrameData]
		}
		enc := make([]byte, len(chunk))
		c.writeSeq = xorMask(enc, chunk, c.key, c.writeSeq)
		f := &Frame{Type: FrameTypeXOR, Cmd: XORCmdData, StreamID: c.streamID, Payload: enc}
		if err := f.EncodeTo(c.conn); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *xorConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	// best-effort STREAM_FIN with a short deadline so we never block
	// indefinitely if the peer has stopped reading.
	_ = c.conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_ = (&Frame{Type: FrameTypeXOR, Cmd: XORCmdStreamFin, StreamID: c.streamID}).EncodeTo(c.conn)
	_ = c.conn.SetWriteDeadline(time.Time{})
	return c.conn.Close()
}

func (c *xorConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }
func (c *xorConn) RemoteAddr() net.Addr {
	if c.remoteRaw != nil {
		return c.remoteRaw
	}
	return c.conn.RemoteAddr()
}
func (c *xorConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *xorConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *xorConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// -----------------------------------------------------------------------------
// Connector / Listener / Handler
// -----------------------------------------------------------------------------

type xorConnector struct {
	user *url.Userinfo
}

// XORConnector creates a Connector that wraps the dialed connection with
// framed XOR encryption. The encryption key comes from the user info
// (`user@key`) of the proxy node.
func XORConnector(user *url.Userinfo) Connector {
	return &xorConnector{user: user}
}

func (c *xorConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *xorConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("xor: %s unsupported", network)
	}
	key := xorKeyOf(c.user)
	if len(key) == 0 {
		return nil, errors.New("xor: empty key")
	}
	return newXORConn(conn, key), nil
}

type xorListener struct {
	net.Listener
	key []byte
}

// XORListener creates a Listener that accepts framed-XOR connections and
// returns net.Conn instances yielding the plaintext stream.
func XORListener(addr string, key []byte) (Listener, error) {
	if len(key) == 0 {
		return nil, errors.New("xor: empty key")
	}
	ln, err := TCPListener(addr)
	if err != nil {
		return nil, err
	}
	return &xorListener{Listener: ln, key: key}, nil
}

func (l *xorListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newXORConn(c, l.key), nil
}

type xorHandler struct {
	options *HandlerOptions
}

// XORHandler is a default handler for an `-L=XOR://` listener when no
// reverse-tunnel bridge is configured. It just forwards the decrypted stream
// to a chain (or auto-detects the protocol like AutoHandler) so that XOR
// behaves like an encrypted-edge variant of the existing forwarders.
func XORHandler(opts ...HandlerOption) Handler {
	h := &xorHandler{}
	h.Init(opts...)
	return h
}

func (h *xorHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *xorHandler) Handle(conn net.Conn) {
	// Without a noport bridge, fall back to auto-detection so that any
	// recognized application protocol (socks/http) inside the encrypted
	// stream is transparently served.
	opts := *h.options
	auto := AutoHandler()
	auto.Init(func(o *HandlerOptions) { *o = opts })
	auto.Handle(conn)
}

// xorBridgeConn wraps a plaintext user-side conn with an explicit RemoteAddr
// so that the A-side handler can see the original 5-tuple even though the
// real underlying TCP belongs to the data queue.
type xorBridgeConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (c *xorBridgeConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}
func (c *xorBridgeConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}

// fakeAddr is a minimal net.Addr implementation used when reconstructing
// 5-tuples carried over admin OPEN_STREAM.
type fakeAddr struct {
	network string
	addr    string
}

func (a *fakeAddr) Network() string { return a.network }
func (a *fakeAddr) String() string  { return a.addr }

// parseFakeAddr returns a fakeAddr from "host:port". network defaults to tcp.
func parseFakeAddr(network, hostport string) net.Addr {
	if hostport == "" {
		return nil
	}
	if network == "" {
		network = "tcp"
	}
	return &fakeAddr{network: network, addr: hostport}
}

// silence unused-import warnings if the symbols become temporarily unused
// during refactors.
var _ = log.Log
var _ = net.SplitHostPort
