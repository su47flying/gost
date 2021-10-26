package gost

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-log/log"
	"github.com/su47flying/gosocks5xor"
	"net"
	"net/url"
	"strconv"
	"time"
)

type xorClientSelector struct {
	methods   []uint8
	User      *url.Userinfo
	TLSConfig *tls.Config
}

func (selector *xorClientSelector) Methods() []uint8 {
	if Debug {
		log.Log("[socks5] methods:", selector.methods)
	}
	return selector.methods
}

func (selector *xorClientSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *xorClientSelector) Select(methods ...uint8) (method uint8) {
	return
}

func (selector *xorClientSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	if Debug {
		log.Log("[socks5] method selected:", method)
	}
	switch method {
	case MethodTLS:
		conn = tls.Client(conn, selector.TLSConfig)

	case gosocks5xor.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Client(conn, selector.TLSConfig)
		}

		var username, password string
		if selector.User != nil {
			username = selector.User.Username()
			password, _ = selector.User.Password()
		}

		req := gosocks5xor.NewUserPassRequest(gosocks5xor.UserPassVer, username, password)
		if err := req.Write(conn); err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", req)
		}
		resp, err := gosocks5xor.ReadUserPassResponse(conn)
		if err != nil {
			log.Log("[socks5]", err)
			return nil, err
		}
		if Debug {
			log.Log("[socks5]", resp)
		}
		if resp.Status != gosocks5xor.Succeeded {
			return nil, gosocks5xor.ErrAuthFailure
		}
	case gosocks5xor.MethodNoAcceptable:
		return nil, gosocks5xor.ErrBadMethod
	}

	return conn, nil
}

type xorServerSelector struct {
	methods []uint8
	// Users     []*url.Userinfo
	Authenticator Authenticator
	TLSConfig     *tls.Config
}

func (selector *xorServerSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *xorServerSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *xorServerSelector) Select(methods ...uint8) (method uint8) {
	if Debug {
		log.Logf("[socks5] %d %d %v", gosocks5xor.Ver5, len(methods), methods)
	}
	method = gosocks5xor.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
	}

	// when Authenticator is set, auth is mandatory
	if selector.Authenticator != nil {
		if method == gosocks5xor.MethodNoAuth {
			method = gosocks5xor.MethodUserPass
		}
		if method == MethodTLS {
			method = MethodTLSAuth
		}
	}

	return
}

func (selector *xorServerSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	if Debug {
		log.Logf("[socks5] %d %d", gosocks5xor.Ver5, method)
	}
	switch method {
	case MethodTLS:
		conn = tls.Server(conn, selector.TLSConfig)

	case gosocks5xor.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, selector.TLSConfig)
		}

		req, err := gosocks5xor.ReadUserPassRequest(conn)
		if err != nil {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return nil, err
		}
		if Debug {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), req.String())
		}

		if selector.Authenticator != nil && !selector.Authenticator.Authenticate(req.Username, req.Password) {
			resp := gosocks5xor.NewUserPassResponse(gosocks5xor.UserPassVer, gosocks5xor.Failure)
			if err := resp.Write(conn); err != nil {
				log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return nil, err
			}
			if Debug {
				log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), resp)
			}
			log.Logf("[socks5] %s - %s: proxy authentication required", conn.RemoteAddr(), conn.LocalAddr())
			return nil, gosocks5xor.ErrAuthFailure
		}

		resp := gosocks5xor.NewUserPassResponse(gosocks5xor.UserPassVer, gosocks5xor.Succeeded)
		if err := resp.Write(conn); err != nil {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return nil, err
		}
		if Debug {
			log.Logf("[socks5] %s - %s: %s", conn.RemoteAddr(), conn.LocalAddr(), resp)
		}
	case gosocks5xor.MethodNoAcceptable:
		return nil, gosocks5xor.ErrBadMethod
	}

	return conn, nil
}

type socks5OverConnector struct {
	User *url.Userinfo
}

// SOCKS5Connector creates a connector for SOCKS5 proxy client.
// It accepts an optional auth info for SOCKS5 Username/Password Authentication.
func SOCKS5OverConnector(user *url.Userinfo) Connector {
	log.Logf("[socks5xor connector]")
	return &socks5OverConnector{User: user}
}

func (c *socks5OverConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *socks5OverConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		cnr := &socks5UDPTunConnector{User: c.User}
		return cnr.ConnectContext(ctx, conn, network, address, options...)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5XORHandshake(conn,
		selectorSocks5HandshakeOption(opts.Selector),
		userSocks5HandshakeOption(user),
		noTLSSocks5HandshakeOption(opts.NoTLS),
	)
	if err != nil {
		return nil, err
	}
	conn = cc

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)
	req := gosocks5xor.NewRequest(gosocks5xor.CmdConnect, &gosocks5xor.Addr{
		Type: gosocks5xor.AddrDomain,
		Host: host,
		Port: uint16(p),
	})
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", req)
	}

	reply, err := gosocks5xor.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if Debug {
		log.Log("[socks5]", reply)
	}

	if reply.Rep != gosocks5xor.Succeeded {
		return nil, errors.New("Service unavailable")
	}

	return conn, nil
}

type socks5OverHandler struct {
	selector *xorServerSelector
	options  *HandlerOptions
}

func (h *socks5OverHandler) Init(options ...HandlerOption) {
	if Debug {
		log.Logf("[socks5xor init")
	}
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}

	tlsConfig := h.options.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	h.selector = &xorServerSelector{ // socks5 server selector
		// Users:     h.options.Users,
		Authenticator: h.options.Authenticator,
		TLSConfig:     tlsConfig,
	}
	// methods that socks5 server supported
	h.selector.AddMethod(
		gosocks5xor.MethodNoAuth,
		gosocks5xor.MethodUserPass,
		MethodTLS,
		MethodTLSAuth,
	)
}

// SOCKS5Handler creates a server Handler for SOCKS5 proxy server.
func SOCKS5OverHandler(opts ...HandlerOption) Handler {
	log.Logf("[socks5xor handler")
	h := &socks5OverHandler{}
	h.Init(opts...)

	return h
}


func (h *socks5OverHandler) Handle(conn net.Conn) {
	defer conn.Close()

	log.Logf("[socks5xor handle")
	conn = gosocks5xor.ServerConn(conn, h.selector)
	req, err := gosocks5xor.ReadRequest(conn)
	if err != nil {
		log.Logf("[socks5] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	if Debug {
		log.Logf("[socks5] %s -> %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), req)
	}
	switch req.Cmd {
	case gosocks5xor.CmdConnect:
		h.handleConnect(conn, req)

	//case gosocks5.CmdBind:
	//	h.handleBind(conn, req)
	//
	//case gosocks5.CmdUdp:
	//	h.handleUDPRelay(conn, req)
	//
	//case CmdMuxBind:
	//	h.handleMuxBind(conn, req)
	//
	//case CmdUDPTun:
	//	h.handleUDPTunnel(conn, req)

	default:
		log.Logf("[socks5] %s - %s : Unrecognized request: %d",
			conn.RemoteAddr(), conn.LocalAddr(), req.Cmd)
	}
}


func (h *socks5OverHandler) handleConnect(conn net.Conn, req *gosocks5xor.Request) {
	host := req.Addr.String()

	log.Logf("[socks5] %s -> %s -> %s",
		conn.RemoteAddr(), h.options.Node.String(), host)

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		log.Logf("[socks5] %s - %s : Unauthorized to tcp connect to %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		rep := gosocks5xor.NewReply(gosocks5xor.NotAllowed, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}
	if h.options.Bypass.Contains(host) {
		log.Logf("[socks5] %s - %s : Bypass %s",
			conn.RemoteAddr(), conn.LocalAddr(), host)
		rep := gosocks5xor.NewReply(gosocks5xor.NotAllowed, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(host)
		if err != nil {
			log.Logf("[socks5] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", host)
		log.Log("[route]", buf.String())

		cc, err = route.Dial(host,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[socks5] %s -> %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		rep := gosocks5xor.NewReply(gosocks5xor.HostUnreachable, nil)
		rep.Write(conn)
		if Debug {
			log.Logf("[socks5] %s <- %s\n%s",
				conn.RemoteAddr(), conn.LocalAddr(), rep)
		}
		return
	}
	defer cc.Close()

	rep := gosocks5xor.NewReply(gosocks5xor.Succeeded, nil)
	if err := rep.Write(conn); err != nil {
		log.Logf("[socks5] %s <- %s : %s",
			conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	if Debug {
		log.Logf("[socks5] %s <- %s\n%s",
			conn.RemoteAddr(), conn.LocalAddr(), rep)
	}
	log.Logf("[socks5] %s <-> %s", conn.RemoteAddr(), host)
	transport(conn, cc)
	log.Logf("[socks5] %s >-< %s", conn.RemoteAddr(), host)
}


func socks5XORHandshake(conn net.Conn, opts ...socks5HandshakeOption) (net.Conn, error) {
	options := socks5HandshakeOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	selector := options.selector
	if selector == nil {
		cs := &xorClientSelector{
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
			User:      options.user,
		}
		cs.AddMethod(
			gosocks5xor.MethodNoAuth,
			gosocks5xor.MethodUserPass,
		)
		if !options.noTLS {
			cs.AddMethod(MethodTLS)
		}
		selector = cs
	}

	cc := gosocks5xor.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		if Debug {
			log.Logf("handle shake error. error:%s", err.Error())
		}
		return nil, err
	}
	if Debug {
		log.Logf("handle shake successfully")
	}
	return cc, nil
}
