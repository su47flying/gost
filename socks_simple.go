package gost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-log/log"
)

// socksSimple is a minimal XOR-encrypted proxy protocol introduced for the
// "noport" reverse-tunnel feature (see NOPORT.md). The wire format is:
//
//   1. The whole TCP stream is XOR encrypted using the password as the key.
//   2. Client → Server : Frame{Type=Data, Cmd=Connect, Payload="tcp host:port"}
//   3. Server → Client : Frame{Type=Data, Cmd=ConnectAck, Payload="ok" | error}
//   4. After "ok", both sides forward raw bytes (still XOR encrypted by xorConn).
//
// On the B host the same socksSimple URL is also reused as the data-queue
// endpoint between B and A; for that role the connection is consumed by the
// noport AdminHub instead of being handled as a normal proxy request. See
// admin.go for details.

// userPass extracts the user/password pair from a URL Userinfo and returns
// the password used as XOR key. An empty Userinfo yields an empty key (no
// encryption), which is rejected by handlers that require auth.
func userPass(u *url.Userinfo) (user, pass string) {
	if u == nil {
		return "", ""
	}
	user = u.Username()
	pass, _ = u.Password()
	return
}

func xorKeyFor(u *url.Userinfo) []byte {
	_, p := userPass(u)
	if p == "" {
		return nil
	}
	return []byte(p)
}

// ---------- client side (Connector + Transporter) ----------

type socksSimpleTransporter struct {
	user *url.Userinfo
}

// SocksSimpleTransporter creates a Transporter for the socksSimple protocol.
// The credentials are used to derive the stream XOR key.
func SocksSimpleTransporter(user *url.Userinfo) Transporter {
	return &socksSimpleTransporter{user: user}
}

func (tr *socksSimpleTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, o := range options {
		o(opts)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}
	var (
		c   net.Conn
		err error
	)
	if opts.Chain == nil {
		c, err = net.DialTimeout("tcp", addr, timeout)
	} else {
		c, err = opts.Chain.Dial(addr)
	}
	if err != nil {
		return nil, err
	}
	return NewXORConn(c, xorKeyFor(tr.user)), nil
}

func (tr *socksSimpleTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *socksSimpleTransporter) Multiplex() bool { return false }

type socksSimpleConnector struct {
	user *url.Userinfo
}

// SocksSimpleConnector creates a Connector for the socksSimple protocol.
func SocksSimpleConnector(user *url.Userinfo) Connector {
	return &socksSimpleConnector{user: user}
}

func (c *socksSimpleConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", addr, options...)
}

func (c *socksSimpleConnector) ConnectContext(ctx context.Context, conn net.Conn, network, addr string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "":
	default:
		return nil, fmt.Errorf("socksSimple: unsupported network %q", network)
	}
	opts := &ConnectOptions{}
	for _, o := range options {
		o(opts)
	}
	if opts.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		defer conn.SetDeadline(time.Time{})
	}
	if err := WriteFrame(conn, Frame{
		Type:    FrameTypeData,
		Cmd:     DataCmdConnect,
		Payload: []byte("tcp " + addr),
	}); err != nil {
		return nil, fmt.Errorf("socksSimple: write CONNECT: %w", err)
	}
	ack, err := ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("socksSimple: read CONNECT_ACK: %w", err)
	}
	if ack.Type != FrameTypeData || ack.Cmd != DataCmdConnectAck {
		return nil, fmt.Errorf("socksSimple: unexpected ack: type=%d cmd=%d", ack.Type, ack.Cmd)
	}
	if string(ack.Payload) != "ok" {
		return nil, fmt.Errorf("socksSimple: connect rejected: %s", string(ack.Payload))
	}
	return conn, nil
}

// ---------- server side (Listener + Handler) ----------

type socksSimpleListener struct {
	net.Listener
	key []byte
	hub *AdminHub // optional: when non-nil, accepted conns may be routed to the hub as data-queue conns
}

// SocksSimpleListener creates a Listener for the socksSimple protocol.
// All accepted connections are XOR-wrapped with the password XOR key so that
// the wrapping is transparent to downstream handlers (or to the AdminHub).
func SocksSimpleListener(addr string, user *url.Userinfo) (Listener, error) {
	return socksSimpleListenerWithHub(addr, user, nil)
}

func socksSimpleListenerWithHub(addr string, user *url.Userinfo, hub *AdminHub) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &socksSimpleListener{Listener: ln, key: xorKeyFor(user), hub: hub}, nil
}

func (l *socksSimpleListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(KeepAliveTime)
	}
	return NewXORConn(c, l.key), nil
}

type socksSimpleHandler struct {
	options *HandlerOptions
	user    *url.Userinfo
	hub     *AdminHub
}

// SocksSimpleHandler creates a Handler for the socksSimple protocol.
// If hub is non-nil the handler will dispatch the very first frame: a
// HELLO frame routes the connection into the hub's data-queue pool;
// a CONNECT frame is handled as a normal user-facing socksSimple request.
func SocksSimpleHandler(user *url.Userinfo, opts ...HandlerOption) Handler {
	h := &socksSimpleHandler{user: user}
	h.Init(opts...)
	return h
}

// SocksSimpleHandlerWithHubExported is the constructor used by route.go
// when both an admin hub and a socksSimple listener exist on the same
// gost process (B side). It is functionally identical to
// SocksSimpleHandler but routes incoming HELLO frames into hub.
func SocksSimpleHandlerWithHubExported(user *url.Userinfo, hub *AdminHub, opts ...HandlerOption) Handler {
	h := &socksSimpleHandler{user: user, hub: hub}
	h.Init(opts...)
	return h
}

func (h *socksSimpleHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *socksSimpleHandler) Handle(conn net.Conn) {
	// Read first frame to dispatch.
	if h.options.Timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(h.options.Timeout))
	}
	first, err := ReadFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Logf("[socksSimple] %s: read first frame: %s", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	if first.Type == FrameTypeData && first.Cmd == DataCmdHello && h.hub != nil {
		// Data-queue connection from Host A.
		h.hub.handleHello(conn, first.Payload)
		return
	}
	if first.Type != FrameTypeData || first.Cmd != DataCmdConnect {
		log.Logf("[socksSimple] %s: unexpected first frame type=%d cmd=%d",
			conn.RemoteAddr(), first.Type, first.Cmd)
		conn.Close()
		return
	}
	h.handleConnect(conn, first.Payload)
}

func (h *socksSimpleHandler) handleConnect(conn net.Conn, payload []byte) {
	defer conn.Close()
	network, addr, err := parseConnectPayload(payload)
	if err != nil {
		_ = WriteFrame(conn, Frame{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte(err.Error())})
		return
	}
	if h.options.Bypass != nil && h.options.Bypass.Contains(addr) {
		_ = WriteFrame(conn, Frame{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte("bypass")})
		return
	}

	var cc net.Conn
	if h.options.Chain.IsEmpty() {
		cc, err = net.DialTimeout(network, addr, h.options.Timeout)
	} else {
		cc, err = h.options.Chain.Dial(addr,
			RetryChainOption(h.options.Retries),
			TimeoutChainOption(h.options.Timeout),
		)
	}
	if err != nil {
		log.Logf("[socksSimple] %s -> %s: %s", conn.RemoteAddr(), addr, err)
		_ = WriteFrame(conn, Frame{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte(err.Error())})
		return
	}
	defer cc.Close()
	if err := WriteFrame(conn, Frame{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte("ok")}); err != nil {
		log.Logf("[socksSimple] %s: write ack: %s", conn.RemoteAddr(), err)
		return
	}
	log.Logf("[socksSimple] %s <-> %s", conn.RemoteAddr(), addr)
	transport(conn, cc)
	log.Logf("[socksSimple] %s >-< %s", conn.RemoteAddr(), addr)
}

func parseConnectPayload(p []byte) (network, addr string, err error) {
	s := strings.TrimSpace(string(p))
	if s == "" {
		return "", "", errors.New("empty CONNECT payload")
	}
	parts := strings.SplitN(s, " ", 2)
	if len(parts) == 1 {
		return "tcp", parts[0], nil
	}
	switch parts[0] {
	case "tcp", "tcp4", "tcp6":
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("unsupported network %q", parts[0])
	}
}
