// Package quictunnel joins gateway QUIC registration and ordinary reverse
// HTTP/3 on a single existing connection. Listener configuration, durable
// authorization, routing, readiness and command state are supplied by callers.
package quictunnel

import (
	"context"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
)

// Session is the transport handle for an accepted gateway peer. The caller must
// consume control messages, gate requests on ready/security/registry state,
// enforce command fences and exclude the session on Done or ack failure.
type Session struct {
	control  *quiccontrol.Carrier
	requests *quichttp.Gateway
}

var _ http.RoundTripper = (*Session)(nil)

// Accept sends ack only after Authorize returns a validated durable decision.
// A context deadline bounds bootstrap; the returned session lives until Close
// or connection/carrier loss. No route is published by this transport package.
func Accept(ctx context.Context, conn *quic.Conn, options quiccontrol.Options, authorize quiccontrol.Authorize) (*Session, error) {
	control, err := quiccontrol.Accept(ctx, conn, options, authorize)
	if err != nil {
		return nil, err
	}
	requests, err := quichttp.NewGateway(control)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	return &Session{control: control, requests: requests}, nil
}

func (s *Session) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.requests.RoundTrip(req)
}
func (s *Session) Send(ctx context.Context, message any) error { return s.control.Send(ctx, message) }
func (s *Session) Receive(ctx context.Context) (any, error)    { return s.control.Receive(ctx) }
func (s *Session) Done() <-chan struct{}                       { return s.control.Done() }
func (s *Session) Err() error                                  { return s.control.Err() }
func (s *Session) Close() error                                { return s.requests.Close() }
