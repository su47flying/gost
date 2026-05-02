package gost

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-log/log"
)

// -----------------------------------------------------------------------------
// MuxQueue: one underlying net.Conn carrying many streams, identified by
// stream_id within XOR-typed frames. The bytes on the wire are *already*
// XOR-encrypted by the producer; MuxQueue itself only does framing & demux.
//
// Concurrency model
//   - one writer mutex serializes EncodeTo on the underlying conn
//   - one reader goroutine demuxes incoming frames into per-stream channels
//   - per-stream net.Conn (muxStream) reads data from a chan []byte
// -----------------------------------------------------------------------------

const muxStreamBufFrames = 64

// MuxQueue multiplexes streams over a single transport connection using
// XOR frames (FrameTypeXOR). It is used by the NOPORT reverse-tunnel
// "data queue" pool. A QueueHello frame is used as queue identification
// at startup; data frames carry an opaque XOR-encrypted payload.
type MuxQueue struct {
	conn    net.Conn
	br      *bufio.Reader
	writeMu sync.Mutex
	id      uint32 // logical queue id (assigned by the side that initiated NEW_QUEUE)

	streamMu sync.Mutex
	streams  map[uint32]*muxStream
	closed   bool
	closeErr error

	// metrics for big-flow detection
	streamBytes map[uint32]*streamMeter

	// callback invoked when a frame arrives for an unknown stream id.
	// When nil, the frame is dropped.
	onUnknownStream func(streamID uint32, f *Frame)

	// callback invoked when QUEUE_HELLO is received (only on accepting side)
	onHello func(queueID uint32)
}

type streamMeter struct {
	mu          sync.Mutex
	currentSec  int64 // unix second
	bytesInSec  int64
	overSeconds int // consecutive seconds above threshold
	locked      bool
}

func newMuxQueue(c net.Conn) *MuxQueue {
	return &MuxQueue{
		conn:        c,
		br:          bufio.NewReader(c),
		streams:     make(map[uint32]*muxStream),
		streamBytes: make(map[uint32]*streamMeter),
	}
}

// run starts the reader loop. Returns when the queue is torn down.
func (q *MuxQueue) run() error {
	defer q.closeAll(io.EOF)
	for {
		f, err := ReadFrame(q.br)
		if err != nil {
			q.setCloseErr(err)
			return err
		}
		if f.Type != FrameTypeXOR {
			// unexpected on a data queue; ignore
			continue
		}
		switch f.Cmd {
		case XORCmdQueueHello:
			if q.onHello != nil {
				q.onHello(f.StreamID)
			}
		case XORCmdData:
			s := q.getStream(f.StreamID)
			if s == nil {
				if q.onUnknownStream != nil {
					q.onUnknownStream(f.StreamID, f)
				}
				continue
			}
			s.feed(f.Payload)
		case XORCmdStreamFin:
			if s := q.getStream(f.StreamID); s != nil {
				s.feedClose()
			}
		}
	}
}

func (q *MuxQueue) getStream(id uint32) *muxStream {
	q.streamMu.Lock()
	defer q.streamMu.Unlock()
	return q.streams[id]
}

// registerStream creates and registers a new muxStream with the given id.
// Returns (stream, true) if newly created, or (existing, false) if it
// already exists (e.g. data arrived before OPEN_STREAM admin command).
func (q *MuxQueue) registerStream(id uint32) (*muxStream, bool) {
	q.streamMu.Lock()
	defer q.streamMu.Unlock()
	if s, ok := q.streams[id]; ok {
		return s, false
	}
	s := newMuxStream(q, id)
	q.streams[id] = s
	return s, true
}

func (q *MuxQueue) removeStream(id uint32) {
	q.streamMu.Lock()
	delete(q.streams, id)
	delete(q.streamBytes, id)
	q.streamMu.Unlock()
}

// writeFrame is goroutine-safe.
func (q *MuxQueue) writeFrame(f *Frame) error {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	if q.closed {
		return net.ErrClosed
	}
	return f.EncodeTo(q.conn)
}

func (q *MuxQueue) Close() error {
	q.streamMu.Lock()
	if q.closed {
		q.streamMu.Unlock()
		return nil
	}
	q.closed = true
	q.streamMu.Unlock()
	q.closeAll(net.ErrClosed)
	return q.conn.Close()
}

func (q *MuxQueue) setCloseErr(err error) {
	q.streamMu.Lock()
	if q.closeErr == nil {
		q.closeErr = err
	}
	q.streamMu.Unlock()
}

func (q *MuxQueue) closeAll(err error) {
	q.streamMu.Lock()
	streams := make([]*muxStream, 0, len(q.streams))
	for _, s := range q.streams {
		streams = append(streams, s)
	}
	q.streams = map[uint32]*muxStream{}
	q.streamMu.Unlock()
	for _, s := range streams {
		s.feedClose()
	}
}

// -----------------------------------------------------------------------------
// muxStream: a net.Conn riding on one stream id of a MuxQueue.
// Read side: bytes pushed via feed() into a chan with a leftover buffer.
// Write side: each Write becomes one or more XORCmdData frames on the queue.
// -----------------------------------------------------------------------------

type muxStream struct {
	q  *MuxQueue
	id uint32

	rCh        chan []byte
	rLeftover  []byte
	rClosed    int32 // atomic
	rDeadline  time.Time
	rDeadlineC chan struct{}

	wMu     sync.Mutex
	wClosed bool

	local  net.Addr
	remote net.Addr
}

func newMuxStream(q *MuxQueue, id uint32) *muxStream {
	return &muxStream{
		q:      q,
		id:     id,
		rCh:    make(chan []byte, muxStreamBufFrames),
		local:  q.conn.LocalAddr(),
		remote: q.conn.RemoteAddr(),
	}
}

func (s *muxStream) feed(b []byte) {
	if atomic.LoadInt32(&s.rClosed) != 0 {
		return
	}
	if len(b) == 0 {
		return
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case s.rCh <- cp:
	default:
		// slow consumer: block. We already check rClosed above.
		s.rCh <- cp
	}
}

func (s *muxStream) feedClose() {
	if atomic.CompareAndSwapInt32(&s.rClosed, 0, 1) {
		close(s.rCh)
	}
}

func (s *muxStream) Read(p []byte) (int, error) {
	if len(s.rLeftover) > 0 {
		n := copy(p, s.rLeftover)
		s.rLeftover = s.rLeftover[n:]
		return n, nil
	}
	b, ok := <-s.rCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, b)
	if n < len(b) {
		s.rLeftover = b[n:]
	}
	return n, nil
}

func (s *muxStream) Write(p []byte) (int, error) {
	s.wMu.Lock()
	defer s.wMu.Unlock()
	if s.wClosed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > xorMaxFrameData {
			chunk = chunk[:xorMaxFrameData]
		}
		f := &Frame{Type: FrameTypeXOR, Cmd: XORCmdData, StreamID: s.id, Payload: chunk}
		if err := s.q.writeFrame(f); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *muxStream) Close() error {
	s.wMu.Lock()
	if s.wClosed {
		s.wMu.Unlock()
		return nil
	}
	s.wClosed = true
	s.wMu.Unlock()
	_ = s.q.writeFrame(&Frame{Type: FrameTypeXOR, Cmd: XORCmdStreamFin, StreamID: s.id})
	s.feedClose()
	s.q.removeStream(s.id)
	return nil
}

func (s *muxStream) LocalAddr() net.Addr                { return s.local }
func (s *muxStream) RemoteAddr() net.Addr               { return s.remote }
func (s *muxStream) SetDeadline(t time.Time) error      { return nil }
func (s *muxStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *muxStream) SetWriteDeadline(t time.Time) error { return nil }

// -----------------------------------------------------------------------------
// AdminHub (B side): manages one A-tunnel session.
// Composition:
//   - one admin control conn (frames of FrameTypeAdmin)
//   - a pool of MuxQueue (data queues coming from A)
//   - allocates stream ids (uint32, starts at 1)
// -----------------------------------------------------------------------------

// HubOptions configure runtime behavior of an AdminHub.
type HubOptions struct {
	PoolSize       int           // initial pool size hint (informational; A controls actual pool)
	BigflowKBps    int           // per-stream rate threshold (KB/s) for lock-in
	BigflowSeconds int           // consecutive seconds above threshold required
	IdleTimeout    time.Duration // close hub if no admin activity for this long
}

// DefaultHubOptions returns reasonable defaults matching NOPORT.md.
func DefaultHubOptions() HubOptions {
	return HubOptions{
		PoolSize:       16,
		BigflowKBps:    256,
		BigflowSeconds: 2,
		IdleTimeout:    90 * time.Second,
	}
}

// AdminHub coordinates one logical NOPORT session between Host A and Host B.
// It is created on Host B when an authenticated admin tunnel arrives.
type AdminHub struct {
	user string
	opts HubOptions

	mu       sync.Mutex
	admin    net.Conn // the admin control conn
	closed   bool
	closeErr error

	pool    []*MuxQueue // round-robin pool
	rrIndex int

	streamSeq    uint32
	queueSeq     uint32 // for NEW_QUEUE allocations
	pendingQueue map[uint32]chan *MuxQueue

	wgServe sync.WaitGroup
}

// noport hub registry; key is the admin user (the URL Userinfo username).
var (
	noportHubsMu sync.Mutex
	noportHubs   = map[string]*AdminHub{}
)

// RegisterHub publishes h under the given user name, replacing any prior hub.
func RegisterHub(user string, h *AdminHub) {
	noportHubsMu.Lock()
	defer noportHubsMu.Unlock()
	if old := noportHubs[user]; old != nil && old != h {
		go old.Close()
	}
	noportHubs[user] = h
}

// LookupHub returns the registered hub for user, or nil.
func LookupHub(user string) *AdminHub {
	noportHubsMu.Lock()
	defer noportHubsMu.Unlock()
	return noportHubs[user]
}

// FirstHub returns any registered hub (used when only one hub is configured
// and -L= listeners do not specify a noport user).
func FirstHub() *AdminHub {
	noportHubsMu.Lock()
	defer noportHubsMu.Unlock()
	for _, h := range noportHubs {
		return h
	}
	return nil
}

// HubCount returns the number of registered hubs.
func HubCount() int {
	noportHubsMu.Lock()
	defer noportHubsMu.Unlock()
	return len(noportHubs)
}

// NewAdminHub creates a new hub bound to the given admin conn.
func NewAdminHub(user string, admin net.Conn, opts HubOptions) *AdminHub {
	if opts.PoolSize <= 0 {
		opts.PoolSize = 16
	}
	if opts.BigflowKBps <= 0 {
		opts.BigflowKBps = 256
	}
	if opts.BigflowSeconds <= 0 {
		opts.BigflowSeconds = 2
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 90 * time.Second
	}
	return &AdminHub{
		user:         user,
		opts:         opts,
		admin:        admin,
		pendingQueue: map[uint32]chan *MuxQueue{},
	}
}

// AddDataQueue registers a freshly-arrived data queue from A.
// queueID is the queue id A advertised in the QueueHello frame.
// Returns when the queue is torn down.
func (h *AdminHub) AddDataQueue(q *MuxQueue, queueID uint32) {
	q.id = queueID
	h.mu.Lock()
	if pendCh, ok := h.pendingQueue[queueID]; ok {
		// Someone is waiting (e.g. a NEW_QUEUE refill). Hand off without
		// adding to pool — they'll add it themselves.
		delete(h.pendingQueue, queueID)
		h.mu.Unlock()
		select {
		case pendCh <- q:
		default:
			// receiver gone; fall through to pool.
			h.mu.Lock()
			h.pool = append(h.pool, q)
			h.mu.Unlock()
		}
	} else {
		h.pool = append(h.pool, q)
		h.mu.Unlock()
	}
	if err := q.run(); err != nil && err != io.EOF {
		log.Logf("[noport hub %s] data queue %d closed: %v", h.user, queueID, err)
	}
	h.removeQueue(q)
}

func (h *AdminHub) removeQueue(q *MuxQueue) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, p := range h.pool {
		if p == q {
			h.pool = append(h.pool[:i], h.pool[i+1:]...)
			return
		}
	}
}

// pickQueue picks the next non-locked pool queue using round-robin.
func (h *AdminHub) pickQueue() *MuxQueue {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.pool)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		idx := (h.rrIndex + i) % n
		q := h.pool[idx]
		// skip locked queues (those reserved for a single big-flow stream)
		q.streamMu.Lock()
		locked := false
		for _, m := range q.streamBytes {
			if m.locked {
				locked = true
				break
			}
		}
		q.streamMu.Unlock()
		if !locked {
			h.rrIndex = (idx + 1) % n
			return q
		}
	}
	// all locked: still pick the round-robin one to avoid starvation.
	q := h.pool[h.rrIndex%n]
	h.rrIndex = (h.rrIndex + 1) % n
	return q
}

// OpenStream is the entry point for a B-side ingress listener. Given an
// already-accepted user net.Conn (`user`), the hub allocates a stream on
// some pool data queue, asks A (via admin) to invoke the named handler
// proto, and bidirectionally pipes data between user <-> stream.
//
// xorKey is the pre-shared XOR key for this hub; user-side bytes are
// XOR-encrypted before being framed onto the data queue.
func (h *AdminHub) OpenStream(ctx context.Context, proto string, xorKey []byte, user net.Conn, dst string) error {
	q := h.pickQueue()
	if q == nil {
		return errors.New("noport: no data queue available")
	}
	id := atomic.AddUint32(&h.streamSeq, 1)
	stream, _ := q.registerStream(id)

	srcAddr := ""
	if a := user.RemoteAddr(); a != nil {
		srcAddr = a.String()
	}
	if dst == "" {
		dst = user.LocalAddr().String()
	}
	payload, err := EncodeTLVs(
		TLVUint32(TLVStreamID, id),
		TLVUint32(TLVQueueID, q.id),
		TLVString(TLVProto, proto),
		TLVBytes(TLVXORKey, xorKey),
		TLVString(TLVSrcAddr, srcAddr),
		TLVString(TLVDstAddr, dst),
		TLVString(TLVNet, "tcp"),
	)
	if err != nil {
		return err
	}
	frame := &Frame{Type: FrameTypeAdmin, Cmd: AdminCmdOpenStream, StreamID: id, Payload: payload}
	if err := h.writeAdmin(frame); err != nil {
		return err
	}

	// bridge user <-> stream, with XOR encryption of the payload bytes.
	xc := &xorConn{conn: stream, br: bufio.NewReader(stream), key: xorKey}
	return bridge(user, xc, h.bigflowMonitor(q, id))
}

// bigflowMonitor returns a function that records bytes for a stream and
// upgrades the stream to "locked" + sends NEW_QUEUE if the threshold is
// crossed. The returned func is intended to be called per Read/Write
// chunk size.
func (h *AdminHub) bigflowMonitor(q *MuxQueue, sid uint32) func(int) {
	thresholdBytes := int64(h.opts.BigflowKBps) * 1024
	requiredSecs := h.opts.BigflowSeconds
	return func(n int) {
		if n <= 0 {
			return
		}
		now := time.Now().Unix()
		q.streamMu.Lock()
		m, ok := q.streamBytes[sid]
		if !ok {
			m = &streamMeter{currentSec: now}
			q.streamBytes[sid] = m
		}
		q.streamMu.Unlock()
		m.mu.Lock()
		if m.currentSec != now {
			if m.bytesInSec >= thresholdBytes {
				m.overSeconds++
			} else {
				m.overSeconds = 0
			}
			m.currentSec = now
			m.bytesInSec = 0
		}
		m.bytesInSec += int64(n)
		needLock := !m.locked && m.overSeconds >= requiredSecs
		if needLock {
			m.locked = true
		}
		m.mu.Unlock()
		if needLock {
			go h.requestNewQueue()
		}
	}
}

// requestNewQueue sends a NEW_QUEUE admin command to A so the pool can
// be refilled to its target size. Best-effort, errors are logged.
func (h *AdminHub) requestNewQueue() {
	qid := atomic.AddUint32(&h.queueSeq, 1) | 0x80000000 // refill ids in upper half to avoid collision
	payload, err := EncodeTLVs(TLVUint32(TLVQueueID, qid))
	if err != nil {
		return
	}
	if err := h.writeAdmin(&Frame{Type: FrameTypeAdmin, Cmd: AdminCmdNewQueue, StreamID: 0, Payload: payload}); err != nil {
		log.Logf("[noport hub %s] NEW_QUEUE failed: %v", h.user, err)
	}
}

func (h *AdminHub) writeAdmin(f *Frame) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.admin == nil {
		return net.ErrClosed
	}
	return f.EncodeTo(h.admin)
}

// ServeAdmin runs the admin control loop for this hub. It consumes PINGs,
// authentication is handled by the caller before invoking ServeAdmin.
func (h *AdminHub) ServeAdmin() error {
	br := bufio.NewReader(h.admin)
	defer h.Close()
	for {
		f, err := ReadFrame(br)
		if err != nil {
			h.closeErr = err
			return err
		}
		if f.Type != FrameTypeAdmin {
			continue
		}
		switch f.Cmd {
		case AdminCmdPing:
			_ = h.writeAdmin(&Frame{Type: FrameTypeAdmin, Cmd: AdminCmdPong, StreamID: f.StreamID})
		case AdminCmdPong:
			// ignore
		case AdminCmdCloseStream:
			tlvs, _ := DecodeTLVs(f.Payload)
			sid := LookupUint32(tlvs, TLVStreamID)
			if sid == 0 {
				sid = f.StreamID
			}
			h.mu.Lock()
			pool := append([]*MuxQueue(nil), h.pool...)
			h.mu.Unlock()
			for _, q := range pool {
				if s := q.getStream(sid); s != nil {
					s.feedClose()
				}
			}
		}
	}
}

// Close shuts the hub and all queues.
func (h *AdminHub) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	pool := h.pool
	h.pool = nil
	admin := h.admin
	h.admin = nil
	h.mu.Unlock()
	for _, q := range pool {
		_ = q.Close()
	}
	if admin != nil {
		_ = admin.Close()
	}
	noportHubsMu.Lock()
	if noportHubs[h.user] == h {
		delete(noportHubs, h.user)
	}
	noportHubsMu.Unlock()
	return nil
}

// -----------------------------------------------------------------------------
// AdminClient (A side): dials B's admin port, authenticates, then maintains
// a pool of data queues and dispatches OPEN_STREAM commands by spawning
// the appropriate handler.
// -----------------------------------------------------------------------------

// AdminClient holds the state of a single A-side reverse tunnel.
type AdminClient struct {
	BAddr      string                                // host:port of B's admin port
	DataAddr   string                                // host:port of B's data-queue (-R=XOR) port
	User       string                                // tunnel user name (also used as auth username)
	AuthKey    []byte                                // tunnel auth key (URL password)
	XORKey     []byte                                // XOR key for data queue payload (== AuthKey by default)
	PoolSize   int                                   // number of data queues to keep open
	HandlerFor func(proto string, h Handler) Handler // optional decorator (testing hook)

	// internal
	mu        sync.Mutex
	admin     net.Conn
	queues    map[uint32]*MuxQueue
	queueSeqA uint32 // queue ids assigned by A (1..)
	closed    bool
}

// Run blocks dialing+serving the admin tunnel. It reconnects with backoff
// on failure. Returns when ctx is cancelled.
func (c *AdminClient) Run(ctx context.Context) {
	if c.PoolSize <= 0 {
		c.PoolSize = 16
	}
	if len(c.XORKey) == 0 {
		c.XORKey = c.AuthKey
	}
	c.queues = map[uint32]*MuxQueue{}

	backoff := 500 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		err := c.session(ctx)
		if err != nil {
			log.Logf("[noport client %s] session: %v", c.User, err)
		}
		// backoff
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (c *AdminClient) session(ctx context.Context) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.BAddr)
	if err != nil {
		return fmt.Errorf("dial admin: %w", err)
	}
	c.mu.Lock()
	c.admin = conn
	c.queues = map[uint32]*MuxQueue{}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.admin != nil {
			c.admin.Close()
			c.admin = nil
		}
		for _, q := range c.queues {
			_ = q.Close()
		}
		c.queues = map[uint32]*MuxQueue{}
		c.mu.Unlock()
	}()

	// AUTH
	authPayload, err := EncodeTLVs(
		TLVString(TLVUser, c.User),
		TLVBytes(TLVAuthKey, c.AuthKey),
		TLVUint16(TLVPoolSize, uint16(c.PoolSize)),
	)
	if err != nil {
		return err
	}
	if err := (&Frame{Type: FrameTypeAdmin, Cmd: AdminCmdAuth, Payload: authPayload}).EncodeTo(conn); err != nil {
		return fmt.Errorf("auth send: %w", err)
	}
	br := bufio.NewReader(conn)
	ack, err := ReadFrame(br)
	if err != nil {
		return fmt.Errorf("auth ack: %w", err)
	}
	if ack.Type != FrameTypeAdmin || ack.Cmd != AdminCmdAuthAck {
		return fmt.Errorf("auth: unexpected response type=%d cmd=%d", ack.Type, ack.Cmd)
	}

	// dial initial pool
	for i := 0; i < c.PoolSize; i++ {
		qid := atomic.AddUint32(&c.queueSeqA, 1)
		if err := c.dialDataQueue(ctx, qid); err != nil {
			log.Logf("[noport client %s] initial data queue %d failed: %v", c.User, qid, err)
		}
	}

	// admin reader loop
	pingT := time.NewTicker(30 * time.Second)
	defer pingT.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-pingT.C:
				_ = (&Frame{Type: FrameTypeAdmin, Cmd: AdminCmdPing}).EncodeTo(conn)
			}
		}
	}()

	for {
		f, err := ReadFrame(br)
		if err != nil {
			return err
		}
		if f.Type != FrameTypeAdmin {
			continue
		}
		switch f.Cmd {
		case AdminCmdPing:
			_ = (&Frame{Type: FrameTypeAdmin, Cmd: AdminCmdPong, StreamID: f.StreamID}).EncodeTo(conn)
		case AdminCmdPong:
			// noop
		case AdminCmdNewQueue:
			tlvs, _ := DecodeTLVs(f.Payload)
			qid := LookupUint32(tlvs, TLVQueueID)
			if qid == 0 {
				qid = atomic.AddUint32(&c.queueSeqA, 1)
			}
			go func(id uint32) {
				if err := c.dialDataQueue(ctx, id); err != nil {
					log.Logf("[noport client %s] refill queue %d: %v", c.User, id, err)
				}
			}(qid)
		case AdminCmdOpenStream:
			tlvs, _ := DecodeTLVs(f.Payload)
			sid := LookupUint32(tlvs, TLVStreamID)
			qid := LookupUint32(tlvs, TLVQueueID)
			proto := LookupString(tlvs, TLVProto)
			xorKey := tlvs[TLVXORKey]
			srcAddr := LookupString(tlvs, TLVSrcAddr)
			dstAddr := LookupString(tlvs, TLVDstAddr)
			c.mu.Lock()
			q := c.queues[qid]
			c.mu.Unlock()
			if q == nil {
				log.Logf("[noport client %s] OPEN_STREAM unknown queue %d", c.User, qid)
				continue
			}
			stream, _ := q.registerStream(sid)
			go c.dispatchStream(stream, proto, xorKey, srcAddr, dstAddr)
		}
	}
}

func (c *AdminClient) dialDataQueue(ctx context.Context, queueID uint32) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.DataAddr)
	if err != nil {
		return err
	}
	// QUEUE_HELLO: stream_id field = queueID; payload is empty (or queueID redundantly)
	if err := (&Frame{Type: FrameTypeXOR, Cmd: XORCmdQueueHello, StreamID: queueID}).EncodeTo(conn); err != nil {
		conn.Close()
		return err
	}
	q := newMuxQueue(conn)
	q.id = queueID
	c.mu.Lock()
	c.queues[queueID] = q
	c.mu.Unlock()
	go func() {
		if err := q.run(); err != nil && err != io.EOF {
			log.Logf("[noport client %s] data queue %d closed: %v", c.User, queueID, err)
		}
		c.mu.Lock()
		if c.queues[queueID] == q {
			delete(c.queues, queueID)
		}
		c.mu.Unlock()
	}()
	return nil
}

// dispatchStream wraps the muxStream with XOR decryption and invokes the
// handler matching proto. Handler factory is supplied via NoportHandlerFor.
func (c *AdminClient) dispatchStream(stream *muxStream, proto string, xorKey []byte, srcAddr, dstAddr string) {
	xc := &xorConn{conn: stream, br: bufio.NewReader(stream), key: xorKey}
	bc := &xorBridgeConn{
		Conn:   xc,
		remote: parseFakeAddr("tcp", srcAddr),
		local:  parseFakeAddr("tcp", dstAddr),
	}
	h := NoportHandlerFor(proto)
	if c.HandlerFor != nil {
		h = c.HandlerFor(proto, h)
	}
	h.Handle(bc)
}

// -----------------------------------------------------------------------------
// Handler factory: maps the `proto` field carried in OPEN_STREAM to a
// gost.Handler running on the A side. Callers may register additional
// handlers via RegisterNoportHandler.
// -----------------------------------------------------------------------------

var (
	noportHandlersMu sync.Mutex
	noportHandlers   = map[string]func() Handler{}
)

// RegisterNoportHandler binds a proto name to a handler factory. Built-in
// names (socks5, http, auto) are always available.
func RegisterNoportHandler(proto string, factory func() Handler) {
	noportHandlersMu.Lock()
	defer noportHandlersMu.Unlock()
	noportHandlers[proto] = factory
}

// NoportHandlerFor returns a fresh handler for the given proto name.
// Falls back to AutoHandler when proto is empty or unknown.
func NoportHandlerFor(proto string) Handler {
	noportHandlersMu.Lock()
	factory := noportHandlers[proto]
	noportHandlersMu.Unlock()
	if factory != nil {
		return factory()
	}
	switch proto {
	case "socks5", "socks":
		return SOCKS5Handler()
	case "http":
		return HTTPHandler()
	case "ss":
		return ShadowHandler()
	case "auto", "":
		return AutoHandler()
	}
	return AutoHandler()
}

// -----------------------------------------------------------------------------
// AdminListener (B side): accepts admin tunnel connections from A, performs
// AUTH, registers the resulting AdminHub, then runs the admin loop.
// -----------------------------------------------------------------------------

// AdminListener listens for incoming admin tunnel connections from Host A.
// It is just a plain TCP listener; pair it with AdminHandler for auth +
// hub registration.
func AdminListener(addr string) (Listener, error) {
	return TCPListener(addr)
}

// AdminHandler authenticates an incoming admin conn, registers the hub,
// and runs the admin control loop.
func AdminHandler(user string, key []byte, opts HubOptions) Handler {
	return &adminHandler{user: user, key: key, opts: opts}
}

type adminHandler struct {
	user    string
	key     []byte
	opts    HubOptions
	options *HandlerOptions
}

func (h *adminHandler) Init(options ...HandlerOption) {
	h.options = &HandlerOptions{}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *adminHandler) Handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	f, err := ReadFrame(br)
	if err != nil {
		log.Logf("[noport admin] read auth: %v", err)
		conn.Close()
		return
	}
	if f.Type != FrameTypeAdmin || f.Cmd != AdminCmdAuth {
		log.Logf("[noport admin] expected AUTH, got type=%d cmd=%d", f.Type, f.Cmd)
		conn.Close()
		return
	}
	tlvs, _ := DecodeTLVs(f.Payload)
	gotUser := LookupString(tlvs, TLVUser)
	gotKey := tlvs[TLVAuthKey]
	if gotUser != h.user || string(gotKey) != string(h.key) {
		log.Logf("[noport admin] auth failed: user=%q", gotUser)
		conn.Close()
		return
	}
	// ack
	if err := (&Frame{Type: FrameTypeAdmin, Cmd: AdminCmdAuthAck}).EncodeTo(conn); err != nil {
		conn.Close()
		return
	}
	// admin conn replaces bufio.Reader; we wrap into a peekConn so that
	// AdminHub.ServeAdmin's bufio.Reader doesn't lose the bytes already
	// consumed.
	pc := &peekConn{Conn: conn, peeked: drainReader(br)}
	hub := NewAdminHub(h.user, pc, h.opts)
	RegisterHub(h.user, hub)
	log.Logf("[noport admin] hub registered for user %q (pool target %d)", h.user, h.opts.PoolSize)
	if err := hub.ServeAdmin(); err != nil && err != io.EOF {
		log.Logf("[noport admin] hub %s closed: %v", h.user, err)
	}
}

// drainReader returns whatever the bufio.Reader has buffered, without
// consuming additional bytes from the underlying conn.
func drainReader(br *bufio.Reader) []byte {
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	b, _ := br.Peek(n)
	out := make([]byte, len(b))
	copy(out, b)
	br.Discard(n)
	return out
}

// peekConn prepends a small slice of pre-read bytes to a net.Conn read stream.
type peekConn struct {
	net.Conn
	peeked []byte
}

func (c *peekConn) Read(p []byte) (int, error) {
	if len(c.peeked) > 0 {
		n := copy(p, c.peeked)
		c.peeked = c.peeked[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// -----------------------------------------------------------------------------
// Data-queue listener (B side): a transport-level XOR listener that, instead
// of returning plaintext conns to a handler, hands the underlying conn to
// the matching AdminHub as a new MuxQueue.
// -----------------------------------------------------------------------------

// NoportDataQueueHandler accepts an A-initiated data queue conn, parses its
// QUEUE_HELLO, locates the hub by `user`, and registers the queue.
func NoportDataQueueHandler(user string) Handler {
	return &dataQueueHandler{user: user}
}

type dataQueueHandler struct {
	user    string
	options *HandlerOptions
}

func (h *dataQueueHandler) Init(options ...HandlerOption) {
	h.options = &HandlerOptions{}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *dataQueueHandler) Handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	f, err := ReadFrame(br)
	if err != nil {
		log.Logf("[noport dq] read hello: %v", err)
		conn.Close()
		return
	}
	if f.Type != FrameTypeXOR || f.Cmd != XORCmdQueueHello {
		log.Logf("[noport dq] expected QUEUE_HELLO, got type=%d cmd=%d", f.Type, f.Cmd)
		conn.Close()
		return
	}
	queueID := f.StreamID
	hub := LookupHub(h.user)
	if hub == nil {
		log.Logf("[noport dq] no hub registered for user %q", h.user)
		conn.Close()
		return
	}
	pc := &peekConn{Conn: conn, peeked: drainReader(br)}
	q := newMuxQueue(pc)
	hub.AddDataQueue(q, queueID)
}

// -----------------------------------------------------------------------------
// Bridge handler (B side): a generic forwarding wrapper. When a `-L=...`
// listener accepts a user conn on B, this handler routes it through the
// (single) registered AdminHub via OpenStream.
// -----------------------------------------------------------------------------

// NoportBridgeHandler wraps another listener's accepted conn and forwards
// it through the noport hub. proto names the application protocol that A
// should run on its end (e.g. "socks5", "http", "auto").
func NoportBridgeHandler(proto string, xorKey []byte) Handler {
	return &bridgeHandler{proto: proto, xorKey: xorKey}
}

type bridgeHandler struct {
	proto   string
	xorKey  []byte
	options *HandlerOptions
}

func (h *bridgeHandler) Init(options ...HandlerOption) {
	h.options = &HandlerOptions{}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *bridgeHandler) Handle(conn net.Conn) {
	defer conn.Close()
	hub := FirstHub()
	if hub == nil {
		log.Logf("[noport bridge] no hub registered, dropping %s", conn.RemoteAddr())
		return
	}
	dst := ""
	if h.options != nil && h.options.Addr != "" {
		dst = h.options.Addr
	}
	if err := hub.OpenStream(context.Background(), h.proto, h.xorKey, conn, dst); err != nil {
		log.Logf("[noport bridge] open stream: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Generic plaintext bridge (used by OpenStream). Copies data both ways
// between two net.Conns; calls metric() on each chunk written for big-flow
// detection.
// -----------------------------------------------------------------------------

func bridge(a, b net.Conn, metric func(int)) error {
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)
	cp := func(dst net.Conn, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					errCh <- werr
					_ = dst.Close()
					_ = src.Close()
					return
				}
				if metric != nil {
					metric(n)
				}
			}
			if err != nil {
				errCh <- err
				_ = dst.Close()
				_ = src.Close()
				return
			}
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil && !errors.Is(e, io.EOF) && !errors.Is(e, net.ErrClosed) {
			return e
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// ParseAdminURL parses a URL like admin://user:key@host:port[?pool=16&bigflow=256:2]
// into its components used by NewAdminHub / AdminClient.
func ParseAdminURL(u *url.URL) (user string, key []byte, opts HubOptions, err error) {
	opts = DefaultHubOptions()
	if u.User == nil {
		err = errors.New("admin: missing user@key")
		return
	}
	user = u.User.Username()
	if pw, ok := u.User.Password(); ok {
		key = []byte(pw)
	}
	q := u.Query()
	if v := q.Get("pool"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			opts.PoolSize = n
		}
	}
	if v := q.Get("bigflow_kbps"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			opts.BigflowKBps = n
		}
	}
	if v := q.Get("bigflow_secs"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			opts.BigflowSeconds = n
		}
	}
	return
}
