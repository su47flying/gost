package gost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/gosocks5"
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
	// dataDialBackoffMin/Max bound the exponential backoff used when
	// Host A fails to dial a data-queue conn back to Host B. The loop
	// retries indefinitely (until the AdminClient is closed) so the
	// pool can self-heal after a network blip without requiring a
	// process restart or a new OPEN_QUEUE from B.
	dataDialBackoffMin = 1 * time.Second
	dataDialBackoffMax = 30 * time.Second
	// refillRequestMinInterval rate-limits OPEN_QUEUE refill requests
	// that the B-side hub sends to A when Acquire times out.
	refillRequestMinInterval = 5 * time.Second
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

	writeMu      sync.Mutex // serializes WriteFrame on conn
	lastRefillMu sync.Mutex
	lastRefill   time.Time

	closeOnce sync.Once
	done      chan struct{}
}

// writeFrame serializes WriteFrame on the admin (control) conn so that
// multiple goroutines (e.g. the read loop sending PONG, and Acquire
// sending refill OPEN_QUEUE) can safely share the same connection.
func (s *adminSession) writeFrame(f Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return WriteFrame(s.conn, f)
}

// requestRefill asks Host A to top up the data-queue pool by sending a
// fresh OPEN_QUEUE frame on the admin channel. Rate-limited so a burst
// of acquire timeouts does not flood A.
func (s *adminSession) requestRefill() {
	s.lastRefillMu.Lock()
	if time.Since(s.lastRefill) < refillRequestMinInterval {
		s.lastRefillMu.Unlock()
		return
	}
	s.lastRefill = time.Now()
	s.lastRefillMu.Unlock()

	payload := fmt.Sprintf("%s|%d", s.hub.dataAddr, s.hub.poolSize)
	if err := s.writeFrame(Frame{
		Type:    FrameTypeAdmin,
		Cmd:     AdminCmdOpenQueue,
		Payload: []byte(payload),
	}); err != nil {
		log.Logf("[noport] refill OPEN_QUEUE to %s: %s", s.user, err)
	} else {
		log.Logf("[noport] refill OPEN_QUEUE sent to user=%s pool=%d data=%s",
			s.user, s.hub.poolSize, s.hub.dataAddr)
	}
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
			// Pool is empty and no new conn arrived in time; nudge
			// Host A to refill in case its data-dial goroutines
			// have all exited (e.g. before the indefinite-retry
			// fix) or are stuck behind a long backoff.
			go s.requestRefill()
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

	if err := s.writeFrame(Frame{Type: FrameTypeAdmin, Cmd: AdminCmdAuthOK}); err != nil {
		log.Logf("[admin] %s: write AUTH_OK: %s", conn.RemoteAddr(), err)
		return
	}
	openPayload := fmt.Sprintf("%s|%d", h.hub.dataAddr, h.hub.poolSize)
	if err := s.writeFrame(Frame{
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
			_ = s.writeFrame(Frame{Type: FrameTypeAdmin, Cmd: AdminCmdPong})
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

	// The data-queue pool is scoped to this admin session. When the session
	// ends (admin conn drops), sessCancel unblocks any slot parked in dial
	// backoff and pool.closeAll() closes the idle conns so slots parked in
	// their blocking read wake up and exit. This prevents old slots from
	// lingering across a reconnect (which would otherwise stack on top of the
	// fresh batch spawned by the new session's OPEN_QUEUE).
	sessCtx, sessCancel := context.WithCancel(context.Background())
	defer sessCancel()
	pool := newDataConnSet()
	defer pool.closeAll()
	poolStarted := false

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
			// The slots are self-maintaining: each rebuilds its own conn on
			// death and refills after being consumed, so the pool holds a
			// steady `count` live conns for the life of the session. Ignore
			// duplicate/refill OPEN_QUEUE frames (B sends these on Acquire
			// timeout) so they don't stack extra goroutines.
			if poolStarted {
				log.Logf("[admin] OPEN_QUEUE %s pool=%d (pool already running; ignored)", dataAddr, count)
				continue
			}
			poolStarted = true
			log.Logf("[admin] OPEN_QUEUE %s pool=%d", dataAddr, count)
			for i := 0; i < count; i++ {
				go c.runDataConn(sessCtx, pool, dataAddr)
			}
		case AdminCmdPong:
			// ok
		}
	}
}

// dataConnSet tracks the live idle data-queue conns of a single admin
// session so they can all be closed when the session ends. add reports
// false once the set has been closed, letting a racing slot retire the
// conn it just dialed instead of leaking it.
type dataConnSet struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func newDataConnSet() *dataConnSet {
	return &dataConnSet{conns: make(map[net.Conn]struct{})}
}

func (p *dataConnSet) add(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *dataConnSet) remove(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *dataConnSet) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

// sleep waits for d, returning false early if the client or session is
// shutting down.
func (c *AdminClient) sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	case <-c.stop:
		return false
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

// runDataConn owns a single slot in the data-queue pool for the life of
// an admin session. It repeatedly establishes one conn to B, sends HELLO,
// then idles in the B-side hub pool until B starts speaking SOCKS5 on it.
//
// Crucially it is a *loop*: whenever a conn is retired — whether it was
// consumed by B, died while idle (network blip / NAT timeout / B closing
// it), or failed HELLO — the same goroutine rebuilds a replacement. This
// keeps the pool at a steady size without depending on B noticing an empty
// pool and re-sending OPEN_QUEUE. When a conn is consumed the serving is
// handed to a detached goroutine (so it survives an admin reconnect) and
// the slot immediately loops to open a fresh idle conn.
func (c *AdminClient) runDataConn(ctx context.Context, pool *dataConnSet, dataAddr string) {
	for {
		if c.isClosed() || ctx.Err() != nil {
			return
		}
		raw, err := c.dialDataConnWithBackoff(ctx, dataAddr)
		if err != nil {
			// client closed or session ended.
			return
		}
		conn := NewXORConn(raw, []byte(c.pass))
		if !pool.add(conn) {
			// Session ended between the dial and here; retire the conn.
			conn.Close()
			return
		}

		if err := WriteFrame(conn, Frame{
			Type:    FrameTypeData,
			Cmd:     DataCmdHello,
			Payload: []byte(c.user + ":" + c.pass),
		}); err != nil {
			log.Logf("[noport] write HELLO: %s", err)
			pool.remove(conn)
			conn.Close()
			// Brief backoff so a peer that keeps dropping us right after
			// connect can't spin this loop hot.
			if !c.sleep(ctx, dataDialBackoffMin) {
				return
			}
			continue
		}

		// Block until B sends the first SOCKS5 byte (could be a long time).
		one := make([]byte, 1)
		if _, err := io.ReadFull(conn, one); err != nil {
			// The idle conn died (network blip, B closed it, or session
			// teardown). Retire it and loop to rebuild the slot so the pool
			// self-heals. A short backoff avoids a hot loop if the conn is
			// being closed immediately on the B side (e.g. auth mismatch).
			pool.remove(conn)
			conn.Close()
			if !c.sleep(ctx, dataDialBackoffMin) {
				return
			}
			continue
		}

		// Consumed by B. Detach serving so it outlives this slot (and admin
		// reconnects), then loop to refill the slot with a fresh idle conn.
		pool.remove(conn)
		go c.serveSocks5(&peekableConn{Conn: conn, buf: one})
	}
}

// dialDataConnWithBackoff keeps retrying TCP dial to the B-side data
// queue address with exponential backoff (capped) until it succeeds, the
// AdminClient is closed, or the admin session ends. This makes the
// data-queue pool self-heal after transient network failures without
// depending on B re-sending OPEN_QUEUE.
func (c *AdminClient) dialDataConnWithBackoff(ctx context.Context, dataAddr string) (net.Conn, error) {
	backoff := dataDialBackoffMin
	attempt := 0
	for {
		if c.isClosed() || ctx.Err() != nil {
			return nil, errors.New("admin client closed")
		}
		raw, err := net.DialTimeout("tcp", dataAddr, DialTimeout)
		if err == nil {
			return raw, nil
		}
		attempt++
		// Log first failure at full detail, subsequent failures more
		// sparsely so a long outage does not spam the log.
		if attempt == 1 || attempt%10 == 0 {
			log.Logf("[noport] data conn dial %s (attempt %d, backoff %s): %s",
				dataAddr, attempt, backoff, err)
		}
		select {
		case <-time.After(backoff):
		case <-c.stop:
			return nil, errors.New("admin client closed")
		case <-ctx.Done():
			return nil, errors.New("admin session ended")
		}
		backoff *= 2
		if backoff > dataDialBackoffMax {
			backoff = dataDialBackoffMax
		}
	}
}

// serveSocks5 runs a one-shot gost SOCKS5 server on the data conn so B
// can drive both TCP CmdConnect and UDP CmdUDPTun against this Host A.
func (c *AdminClient) serveSocks5(conn net.Conn) {
	h := SOCKS5Handler()
	h.Handle(conn)
}

// peekableConn prepends a small buffer to the next reads of the
// underlying net.Conn while transparently delegating everything else.
type peekableConn struct {
	net.Conn
	buf []byte
}

func (p *peekableConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		if len(p.buf) == 0 {
			p.buf = nil
		}
		return n, nil
	}
	return p.Conn.Read(b)
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
	// Deprecated frame-based path; retained as a no-op to keep the
	// symbol around while the wire protocol switches to native SOCKS5.
	_ = conn
	_ = payload
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
	// A's data conn worker now serves a one-shot SOCKS5 server on the
	// post-HELLO conn, so we drive it as a normal SOCKS5 client. This
	// lets B's user-facing handlers transparently relay both TCP
	// CmdConnect and UDP CmdUDPTun (for QUIC) through the tunnel.
	cc, err := socks5Handshake(conn, noTLSSocks5HandshakeOption(true))
	if err != nil {
		return nil, fmt.Errorf("noport: socks5 handshake: %w", err)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("noport: parse addr: %w", err)
	}
	portN, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("noport: parse port: %w", err)
	}
	req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: uint16(portN),
	})
	if err := req.Write(cc); err != nil {
		return nil, fmt.Errorf("noport: write CONNECT: %w", err)
	}
	reply, err := gosocks5.ReadReply(cc)
	if err != nil {
		return nil, fmt.Errorf("noport: read CONNECT reply: %w", err)
	}
	if reply.Rep != gosocks5.Succeeded {
		return nil, fmt.Errorf("noport: connect rejected (rep=%d)", reply.Rep)
	}
	return cc, nil
}
