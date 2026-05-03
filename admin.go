package gost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
)

// ============================================================================
// noport / admin protocol — B side hub
// ============================================================================
//
// AdminHub is the central state for the B-host side of the noport reverse
// tunnel. It holds:
//
//   - per-user adminSession state (one A connected per user)
//   - per-user idle pools of HELLO'd data-queue conns received from A
//
// When a user-facing -L listener on B needs to dial out, it goes through a
// Chain whose Transporter.Dial calls hub.Acquire(): a HELLO'd data conn is
// popped from the pool and returned. The Connector then writes a CONNECT
// frame and reads CONNECT_ACK; on "ok" the conn is returned to the caller
// for raw bidirectional traffic.

const (
	defaultPoolSize     = 8
	adminPingInterval   = 30 * time.Second
	adminAuthTimeout    = 10 * time.Second
	adminAcquireTimeout = 30 * time.Second
)

var (
	// ErrNoSession indicates no Host A is currently registered with the hub.
	ErrNoSession = errors.New("noport: no admin session registered")
	// ErrAcquireTimeout means no data-queue conn became available in time.
	ErrAcquireTimeout = errors.New("noport: timeout acquiring data-queue conn")
	// ErrAuthFailed indicates an A→B authentication failure.
	ErrAuthFailed = errors.New("noport: auth failed")
	// ErrSessionExists indicates a duplicate AUTH from a second A for the same user.
	ErrSessionExists = errors.New("noport: session already exists for user")
)

// AdminHub coordinates admin sessions (A→B control channel) and data-queue
// conns (A→B HELLO'd tunnel sockets) on the B host.
type AdminHub struct {
	dataAddr string // host:port advertised to A so it knows where to dial data conns
	poolSize int

	mu       sync.Mutex
	sessions map[string]*adminSession // keyed by user name
}

// NewAdminHub creates a hub. dataAddr is the externally reachable
// host:port of the matching socksSimple listener that A should dial for
// data-queue conns. poolSize is the target idle-pool size per A.
func NewAdminHub(dataAddr string, poolSize int) *AdminHub {
	if poolSize <= 0 {
		poolSize = defaultPoolSize
	}
	return &AdminHub{
		dataAddr: dataAddr,
		poolSize: poolSize,
		sessions: make(map[string]*adminSession),
	}
}

// DataAddr returns the data-queue endpoint advertised to A.
func (h *AdminHub) DataAddr() string { return h.dataAddr }

// SetAdminHubDataAddr is used by the CLI to fill in the dataAddr after
// the socksSimple listener has bound (e.g. on 127.0.0.1:0 in tests).
func SetAdminHubDataAddr(h *AdminHub, addr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dataAddr = addr
}

// PoolSize returns the configured idle-pool size.
func (h *AdminHub) PoolSize() int { return h.poolSize }

// SessionCount returns the number of active admin sessions.
func (h *AdminHub) SessionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

type adminSession struct {
	user string
	conn net.Conn // admin (control) conn, XOR-wrapped
	hub  *AdminHub

	queueMu sync.Mutex
	queue   []net.Conn
	signal  chan struct{} // signaled when a new conn is enqueued

	closeOnce sync.Once
	done      chan struct{}
}

func newAdminSession(hub *AdminHub, user string, conn net.Conn) *adminSession {
	return &adminSession{
		user:   user,
		conn:   conn,
		hub:    hub,
		signal: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

func (s *adminSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.conn.Close()
		s.queueMu.Lock()
		for _, c := range s.queue {
			_ = c.Close()
		}
		s.queue = nil
		s.queueMu.Unlock()
	})
}

func (s *adminSession) push(c net.Conn) {
	select {
	case <-s.done:
		_ = c.Close()
		return
	default:
	}
	s.queueMu.Lock()
	s.queue = append(s.queue, c)
	s.queueMu.Unlock()
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

func (s *adminSession) pop() (net.Conn, bool) {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	for len(s.queue) > 0 {
		c := s.queue[0]
		s.queue = s.queue[1:]
		// Drop conns that the peer already closed.
		if isConnAlive(c) {
			return c, true
		}
		_ = c.Close()
	}
	return nil, false
}

// isConnAlive does a non-blocking 1-byte peek to detect a half-closed conn.
// XOR-wrapped conns expose SetReadDeadline through the embedded net.Conn.
func isConnAlive(c net.Conn) bool {
	type deadliner interface{ SetReadDeadline(time.Time) error }
	d, ok := c.(deadliner)
	if !ok {
		return true
	}
	if err := d.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
		return true // can't check; assume alive
	}
	defer d.SetReadDeadline(time.Time{})
	var b [1]byte
	n, err := c.Read(b[:])
	if n > 0 {
		// Unexpected data on an idle data-queue conn — discard.
		return false
	}
	if err == nil {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

// register attempts to register a new session for user. Returns
// ErrSessionExists if one already exists.
func (h *AdminHub) register(user string, conn net.Conn) (*adminSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.sessions[user]; ok {
		return nil, ErrSessionExists
	}
	s := newAdminSession(h, user, conn)
	h.sessions[user] = s
	return s, nil
}

func (h *AdminHub) unregister(s *adminSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.sessions[s.user]; ok && cur == s {
		delete(h.sessions, s.user)
	}
	s.close()
}

// pickSession returns any active session (round-robin not implemented
// since the spec calls for a single A; if multiple A users are registered
// the first one is picked).
func (h *AdminHub) pickSession() *adminSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sessions {
		return s
	}
	return nil
}

// Acquire returns a HELLO'd, XOR-wrapped data-queue conn from any
// registered session, blocking up to adminAcquireTimeout.
func (h *AdminHub) Acquire(ctx context.Context) (net.Conn, error) {
	s := h.pickSession()
	if s == nil {
		return nil, ErrNoSession
	}
	if c, ok := s.pop(); ok {
		return c, nil
	}
	timer := time.NewTimer(adminAcquireTimeout)
	defer timer.Stop()
	for {
		select {
		case <-s.signal:
			if c, ok := s.pop(); ok {
				return c, nil
			}
		case <-s.done:
			return nil, ErrNoSession
		case <-timer.C:
			return nil, ErrAcquireTimeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// handleHello is invoked by socksSimpleHandler when the first frame on a
// just-accepted socksSimple conn is a HELLO frame: the conn is an A→B
// data-queue socket. It validates auth and pushes the conn into the
// matching session's idle pool.
func (h *AdminHub) handleHello(conn net.Conn, payload []byte) {
	user, pass, ok := splitAuth(string(payload))
	if !ok {
		log.Logf("[noport] hello: bad auth payload from %s", conn.RemoteAddr())
		_ = conn.Close()
		return
	}
	h.mu.Lock()
	s, exists := h.sessions[user]
	h.mu.Unlock()
	if !exists {
		log.Logf("[noport] hello: no admin session for user %q (from %s)", user, conn.RemoteAddr())
		_ = conn.Close()
		return
	}
	if !checkSessionPassword(s, pass) {
		log.Logf("[noport] hello: bad password for user %q (from %s)", user, conn.RemoteAddr())
		_ = conn.Close()
		return
	}
	s.push(conn)
}

// sessionPasswords stores the validated password per active session so that
// HELLO frames can be checked without re-running the authenticator. It
// lives outside the mutex-protected map intentionally — entries are only
// written at register time and cleared at unregister time, both in the
// AdminHandler goroutine.
var sessionPasswords sync.Map // map[*adminSession]string

func setSessionPassword(s *adminSession, pass string) { sessionPasswords.Store(s, pass) }
func clearSessionPassword(s *adminSession)            { sessionPasswords.Delete(s) }
func checkSessionPassword(s *adminSession, pass string) bool {
	v, ok := sessionPasswords.Load(s)
	if !ok {
		return false
	}
	return v.(string) == pass
}

func splitAuth(s string) (user, pass string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// ============================================================================
// AdminHandler — B-side server for -R=admin
// ============================================================================

type adminHandler struct {
	options *HandlerOptions
	user    *url.Userinfo
	hub     *AdminHub
}

// AdminHandler creates a server Handler for the noport admin (-R=admin)
// channel on the B host. It validates auth, registers the session in hub
// and sends OPEN_QUEUE telling A where to dial data-queue conns.
func AdminHandler(user *url.Userinfo, hub *AdminHub, opts ...HandlerOption) Handler {
	h := &adminHandler{user: user, hub: hub}
	h.Init(opts...)
	return h
}

func (h *adminHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *adminHandler) Handle(conn net.Conn) {
	conn = NewXORConn(conn, xorKeyFor(h.user))
	_ = conn.SetReadDeadline(time.Now().Add(adminAuthTimeout))
	first, err := ReadFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Logf("[admin] %s: read AUTH: %s", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	if first.Type != FrameTypeAdmin || first.Cmd != AdminCmdAuth {
		log.Logf("[admin] %s: first frame is not AUTH (type=%d cmd=%d)",
			conn.RemoteAddr(), first.Type, first.Cmd)
		conn.Close()
		return
	}
	user, pass, ok := splitAuth(string(first.Payload))
	if !ok {
		writeFail(conn, "bad auth payload")
		return
	}
	if !h.checkAuth(user, pass) {
		writeFail(conn, "auth failed")
		return
	}
	s, err := h.hub.register(user, conn)
	if err != nil {
		writeFail(conn, err.Error())
		return
	}
	setSessionPassword(s, pass)
	defer clearSessionPassword(s)
	defer h.hub.unregister(s)

	if err := WriteFrame(conn, Frame{Type: FrameTypeAdmin, Cmd: AdminCmdAuthOK}); err != nil {
		log.Logf("[admin] %s: write AUTH_OK: %s", conn.RemoteAddr(), err)
		return
	}
	openPayload := fmt.Sprintf("%s|%d", h.hub.dataAddr, h.hub.poolSize)
	if err := WriteFrame(conn, Frame{
		Type:    FrameTypeAdmin,
		Cmd:     AdminCmdOpenQueue,
		Payload: []byte(openPayload),
	}); err != nil {
		log.Logf("[admin] %s: write OPEN_QUEUE: %s", conn.RemoteAddr(), err)
		return
	}
	log.Logf("[admin] session registered: user=%s peer=%s pool=%d data=%s",
		user, conn.RemoteAddr(), h.hub.poolSize, h.hub.dataAddr)

	// Loop: read pings (and ignore unknown commands).
	for {
		f, err := ReadFrame(conn)
		if err != nil {
			log.Logf("[admin] session %s closed: %s", user, err)
			return
		}
		if f.Type == FrameTypeAdmin && f.Cmd == AdminCmdPing {
			_ = WriteFrame(conn, Frame{Type: FrameTypeAdmin, Cmd: AdminCmdPong})
		}
	}
}

func (h *adminHandler) checkAuth(user, pass string) bool {
	if h.options.Authenticator != nil {
		return h.options.Authenticator.Authenticate(user, pass)
	}
	if h.user == nil {
		return true
	}
	wantUser, wantPass := userPass(h.user)
	return user == wantUser && pass == wantPass
}

func writeFail(conn net.Conn, reason string) {
	_ = WriteFrame(conn, Frame{Type: FrameTypeAdmin, Cmd: AdminCmdAuthFail, Payload: []byte(reason)})
	conn.Close()
}

// AdminListener creates a plain TCP listener used for the -R=admin endpoint.
// XOR wrapping is applied inside AdminHandler.Handle (so that the listener
// itself can be the standard TCPListener).
func AdminListener(addr string) (Listener, error) {
	return TCPListener(addr)
}

// ============================================================================
// AdminClient — A-side client for -T=admin
// ============================================================================

// AdminClient runs on Host A. It maintains a long-lived admin connection
// to Host B, authenticates, and on every received OPEN_QUEUE message it
// keeps a target number of HELLO'd data-queue conns open to B. Each data
// conn waits for a CONNECT frame from B; on receipt it dials the target
// itself and bridges raw bytes after writing CONNECT_ACK("ok").
type AdminClient struct {
	addr string // B admin host:port
	user string
	pass string

	stop   chan struct{}
	mu     sync.Mutex
	closed bool
}

// NewAdminClient creates an AdminClient for an -T=admin entry.
func NewAdminClient(addr string, user *url.Userinfo) *AdminClient {
	u, p := userPass(user)
	return &AdminClient{
		addr: addr,
		user: u,
		pass: p,
		stop: make(chan struct{}),
	}
}

// Start begins the admin loop in a background goroutine and returns
// immediately. It is safe to call Start once.
func (c *AdminClient) Start() {
	go c.run()
}

// Close terminates the client and any data-queue workers it spawned.
func (c *AdminClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.stop)
}

func (c *AdminClient) isClosed() bool {
	select {
	case <-c.stop:
		return true
	default:
		return false
	}
}

func (c *AdminClient) run() {
	backoff := time.Second
	for !c.isClosed() {
		err := c.session()
		if c.isClosed() {
			return
		}
		log.Logf("[admin] connection lost: %s; reconnecting in %s", err, backoff)
		select {
		case <-time.After(backoff):
		case <-c.stop:
			return
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (c *AdminClient) session() error {
	raw, err := net.DialTimeout("tcp", c.addr, DialTimeout)
	if err != nil {
		return err
	}
	conn := NewXORConn(raw, []byte(c.pass))
	defer conn.Close()

	if err := WriteFrame(conn, Frame{
		Type:    FrameTypeAdmin,
		Cmd:     AdminCmdAuth,
		Payload: []byte(c.user + ":" + c.pass),
	}); err != nil {
		return fmt.Errorf("write AUTH: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(adminAuthTimeout))
	resp, err := ReadFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("read AUTH response: %w", err)
	}
	if resp.Type != FrameTypeAdmin {
		return fmt.Errorf("unexpected AUTH response type: %d", resp.Type)
	}
	switch resp.Cmd {
	case AdminCmdAuthOK:
	case AdminCmdAuthFail:
		return fmt.Errorf("%w: %s", ErrAuthFailed, string(resp.Payload))
	default:
		return fmt.Errorf("unexpected AUTH response cmd: %d", resp.Cmd)
	}

	log.Logf("[admin] authenticated to %s as %s", c.addr, c.user)

	// Heartbeat goroutine.
	go c.heartbeat(conn)

	for {
		f, err := ReadFrame(conn)
		if err != nil {
			return fmt.Errorf("admin read: %w", err)
		}
		if f.Type != FrameTypeAdmin {
			continue
		}
		switch f.Cmd {
		case AdminCmdOpenQueue:
			dataAddr, count, err := parseOpenQueue(f.Payload)
			if err != nil {
				log.Logf("[admin] bad OPEN_QUEUE: %s", err)
				continue
			}
			dataAddr = c.resolveDataAddr(dataAddr)
			log.Logf("[admin] OPEN_QUEUE %s pool=%d", dataAddr, count)
			for i := 0; i < count; i++ {
				go c.runDataConn(dataAddr)
			}
		case AdminCmdPong:
			// ok
		}
	}
}

func (c *AdminClient) heartbeat(conn net.Conn) {
	t := time.NewTicker(adminPingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if err := WriteFrame(conn, Frame{Type: FrameTypeAdmin, Cmd: AdminCmdPing}); err != nil {
				return
			}
		}
	}
}

func parseOpenQueue(p []byte) (string, int, error) {
	parts := strings.SplitN(string(p), "|", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("malformed payload %q", string(p))
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || n <= 0 {
		return "", 0, fmt.Errorf("bad count %q", parts[1])
	}
	return strings.TrimSpace(parts[0]), n, nil
}

// runDataConn opens one data-queue conn to B, sends HELLO, then waits for
// a CONNECT frame. On receipt it dials the target, replies CONNECT_ACK and
// bridges. After the connection is consumed it spawns a fresh worker so
// that the idle-pool size on B stays approximately constant.
func (c *AdminClient) runDataConn(dataAddr string) {
	if c.isClosed() {
		return
	}
	raw, err := net.DialTimeout("tcp", dataAddr, DialTimeout)
	if err != nil {
		log.Logf("[noport] data conn dial %s: %s", dataAddr, err)
		// Retry once after a small delay.
		select {
		case <-time.After(time.Second):
		case <-c.stop:
			return
		}
		raw, err = net.DialTimeout("tcp", dataAddr, DialTimeout)
		if err != nil {
			log.Logf("[noport] data conn dial %s (retry): %s", dataAddr, err)
			return
		}
	}
	conn := NewXORConn(raw, []byte(c.pass))

	if err := WriteFrame(conn, Frame{
		Type:    FrameTypeData,
		Cmd:     DataCmdHello,
		Payload: []byte(c.user + ":" + c.pass),
	}); err != nil {
		log.Logf("[noport] write HELLO: %s", err)
		conn.Close()
		return
	}

	// Now block until B sends a CONNECT (this can take a long time).
	f, err := ReadFrame(conn)
	if err != nil {
		conn.Close()
		return
	}
	if f.Type != FrameTypeData || f.Cmd != DataCmdConnect {
		log.Logf("[noport] unexpected frame on data conn: type=%d cmd=%d", f.Type, f.Cmd)
		conn.Close()
		return
	}

	// Refill the pool: this conn has been consumed.
	go c.runDataConn(dataAddr)

	c.handleConnect(conn, f.Payload)
}

// resolveDataAddr substitutes B's admin host for a wildcard/empty host
// in the dataAddr advertised via OPEN_QUEUE, so A can actually dial it
// when B has only bound 0.0.0.0/[::] for its socksSimple listener.
func (c *AdminClient) resolveDataAddr(dataAddr string) string {
	host, port, err := net.SplitHostPort(dataAddr)
	if err != nil {
		return dataAddr
	}
	switch host {
	case "", "0.0.0.0", "::":
		adminHost, _, err := net.SplitHostPort(c.addr)
		if err != nil || adminHost == "" {
			return dataAddr
		}
		return net.JoinHostPort(adminHost, port)
	}
	return dataAddr
}

func (c *AdminClient) handleConnect(conn net.Conn, payload []byte) {
	defer conn.Close()
	network, addr, err := parseConnectPayload(payload)
	if err != nil {
		_ = WriteFrame(conn, Frame{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte(err.Error())})
		return
	}
	target, err := net.DialTimeout(network, addr, DialTimeout)
	if err != nil {
		log.Logf("[noport] target dial %s: %s", addr, err)
		_ = WriteFrame(conn, Frame{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte(err.Error())})
		return
	}
	defer target.Close()
	if err := WriteFrame(conn, Frame{Type: FrameTypeData, Cmd: DataCmdConnectAck, Payload: []byte("ok")}); err != nil {
		return
	}
	log.Logf("[noport] %s <-> %s", conn.RemoteAddr(), addr)
	transport(conn, target)
	log.Logf("[noport] %s >-< %s", conn.RemoteAddr(), addr)
}

// ============================================================================
// noport hub Chain — used by user-facing -L handlers on B to tunnel via A
// ============================================================================

// hubTransporter.Dial returns a HELLO'd data-queue conn from the hub.
// hubConnector.ConnectContext writes CONNECT and reads CONNECT_ACK.
type hubTransporter struct{ hub *AdminHub }
type hubConnector struct{}

// NewHubChain creates a *Chain whose single node is backed by the given
// AdminHub. User-facing -L=socks5/http/... handlers on B can use this
// chain; their outbound dials will tunnel through Host A.
func NewHubChain(hub *AdminHub) *Chain {
	node := Node{
		Addr:      "noport-hub",
		Host:      "noport-hub",
		Protocol:  "noport",
		Transport: "noport",
		Client: &Client{
			Connector:   &hubConnector{},
			Transporter: &hubTransporter{hub: hub},
		},
		marker: &failMarker{},
	}
	c := NewChain(node)
	return c
}

func (t *hubTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), adminAcquireTimeout)
	defer cancel()
	return t.hub.Acquire(ctx)
}

func (t *hubTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (t *hubTransporter) Multiplex() bool { return false }

func (c *hubConnector) Connect(conn net.Conn, addr string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", addr, options...)
}

func (c *hubConnector) ConnectContext(ctx context.Context, conn net.Conn, network, addr string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "":
		network = "tcp"
	default:
		return nil, fmt.Errorf("noport: unsupported network %q", network)
	}
	if err := WriteFrame(conn, Frame{
		Type:    FrameTypeData,
		Cmd:     DataCmdConnect,
		Payload: []byte(network + " " + addr),
	}); err != nil {
		return nil, fmt.Errorf("noport: write CONNECT: %w", err)
	}
	ack, err := ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("noport: read CONNECT_ACK: %w", err)
	}
	if ack.Type != FrameTypeData || ack.Cmd != DataCmdConnectAck {
		return nil, fmt.Errorf("noport: unexpected ack type=%d cmd=%d", ack.Type, ack.Cmd)
	}
	if string(ack.Payload) != "ok" {
		return nil, fmt.Errorf("noport: connect rejected: %s", string(ack.Payload))
	}
	return conn, nil
}
