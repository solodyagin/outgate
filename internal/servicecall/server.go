// Package servicecall serves signed interservice calls on a dedicated mTLS listener.
package servicecall

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/solodyagin/outgate-sdk/delegation"
	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
)

var (
	ErrConfig      = errors.New("outgate: invalid service listener configuration")
	ErrForbidden   = errors.New("outgate: service call forbidden")
	ErrRateLimited = errors.New("outgate: service call rate limited")
)

type Peer struct {
	ServiceID, InstanceID string
	SPKI                  [32]byte
	Certificate           *x509.Certificate // read-only verified leaf
}

type Call struct {
	Peer                          Peer
	GrantID, Target, Method, Path string
	RawURI                        string // original signed URI; Path is already decoded
	KeyID                         string
	User                          delegation.Identity
	HasUser                       bool
}

type Transport interface {
	http.RoundTripper
	Handle() *registry.Session
}

type Recipient struct {
	Transport  Transport
	Key        delivery.Key
	ValidUntil time.Time // optional additional security deadline
}

type Replay interface {
	httpsig.ReplayStore
	Ready(context.Context) error
}

type Config struct {
	Certificate        tls.Certificate
	ClientRoots        *x509.CertPool
	TrustDomain        string
	AllowedAuthorities []string // exact Host/:authority values, including configured ports
	AttributeHeaders   map[string]string
	Issuer             *delegation.Verifier
	Routes             *registry.Registry
	Replay             Replay
	ReplayNamespace    string

	// Authenticate applies caller rate limits, grant/SPKI binding, credential
	// revocation and accepted key lookup. GrantID and KeyID are peer hints.
	Authenticate func(context.Context, Peer, string, string) (delivery.Key, error)
	// Authorize checks current control/revocation and path/method/delegation
	// policy. The deadline applies to the whole exchange.
	Authorize func(context.Context, Call) (time.Time, error)
	// Resolve selects a live transport and a distinct recipient signing key
	// from trusted state, including the selected recipient's revocation state.
	Resolve func(context.Context, registry.Decision) (Recipient, error)
	// Revalidate checks the same call/key/recipient after durable replay commit.
	// It must not select another session, reserve another nonce or send a request.
	Revalidate func(context.Context, Call, delivery.Key, registry.Decision, Recipient) error
	// RewriteResponse optionally overrides the built-in mount header rewriting.
	// It runs only for routes that negotiated rewriting, before headers are sent.
	RewriteResponse func(registry.Decision, *http.Response) error
}

type handler struct {
	config      Config
	verifier    *delivery.Verifier
	signer      *httpsig.Profile
	authorities map[string]struct{}
}

// NewServer prepares the dedicated mTLS listener. The runtime owns listener
// startup, shutdown, connection quotas, security state and replay lifecycle.
func NewServer(config Config) (*http.Server, error) {
	if len(config.AllowedAuthorities) == 0 {
		return nil, ErrConfig
	}
	authorities := make(map[string]struct{}, len(config.AllowedAuthorities))
	for _, host := range config.AllowedAuthorities {
		if v1.ValidateHTTPRequestMetadata(http.MethodGet, host, "/", []v1.Header{}) != nil {
			return nil, ErrConfig
		}
		if _, duplicate := authorities[host]; duplicate {
			return nil, ErrConfig
		}
		authorities[host] = struct{}{}
	}
	authority, err := url.Parse("spiffe://" + config.TrustDomain)
	if err != nil || authority.Hostname() == "" || authority.Hostname() != config.TrustDomain ||
		authority.String() != "spiffe://"+config.TrustDomain || strings.ContainsAny(config.TrustDomain, ":[]") ||
		len(config.Certificate.Certificate) == 0 || config.Certificate.PrivateKey == nil || config.ClientRoots == nil ||
		config.Routes == nil || config.Replay == nil || !httpsig.ValidReplayNamespace(config.ReplayNamespace) ||
		config.Authenticate == nil || config.Authorize == nil || config.Resolve == nil {
		return nil, ErrConfig
	}
	verifier, err := delivery.New(delivery.Config{Leg: httpsig.Call, AttributeHeaders: config.AttributeHeaders, JWT: config.Issuer})
	if err != nil {
		return nil, ErrConfig
	}
	attributes := make([]string, 0, len(config.AttributeHeaders))
	for _, name := range config.AttributeHeaders {
		name = strings.ToLower(name)
		if isForwardingHeader(name) {
			return nil, ErrConfig
		}
		attributes = append(attributes, name)
	}
	signer, err := httpsig.New(httpsig.Config{Leg: httpsig.Gateway, AttributeHeaders: attributes})
	if err != nil {
		return nil, ErrConfig
	}
	return &http.Server{
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: config.ClientRoots.Clone(), Certificates: []tls.Certificate{config.Certificate}},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32768,
		Handler:           &handler{config: config, verifier: verifier, signer: signer, authorities: authorities},
	}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	now := time.Now()
	peer, ok := verifiedPeer(req.TLS, h.config.TrustDomain, now)
	if !ok {
		reject(w, http.StatusUnauthorized)
		return
	}
	if _, allowed := h.authorities[req.Host]; !allowed {
		reject(w, http.StatusMisdirectedRequest)
		return
	}
	meta, fields, err := requestMetadata(req)
	if err != nil {
		reject(w, http.StatusUnauthorized)
		return
	}
	path, _ := v1.DecodeRoutePath(meta.RawURI) // metadata validation already checked it
	if v1.MatchesPrefix("/outgate/discovery", path) || v1.MatchesPrefix("/outgate/revocations", path) {
		reject(w, http.StatusNotFound)
		return
	}
	input, err := httpsig.ParseSignatureInput(fields.Get("Signature-Input"))
	if err != nil || input.Label != httpsig.Call || fields.Get("X-Outgate-Caller-Service") != peer.ServiceID ||
		fields.Get("X-Outgate-Deployment-Grant-Id") == "" {
		reject(w, http.StatusUnauthorized)
		return
	}
	deadline := now.Add(5 * time.Second)
	if peer.Certificate.NotAfter.Before(deadline) {
		deadline = peer.Certificate.NotAfter
	}
	admission, cancel := context.WithDeadline(req.Context(), deadline)
	defer cancel()
	grantID := fields.Get("X-Outgate-Deployment-Grant-Id")
	key, err := h.config.Authenticate(admission, peer, grantID, input.Params.KeyID)
	if err != nil {
		reject(w, statusFor(err))
		return
	}
	binding := delivery.Binding{Caller: peer.ServiceID, Target: fields.Get("X-Outgate-Target-Service"), GrantID: grantID}
	verified, err := h.verifier.Verify(meta, key, binding, time.Now())
	if err != nil {
		reject(w, http.StatusUnauthorized)
		return
	}
	identity, hasUser := verified.Identity()
	call := Call{Peer: peer, GrantID: grantID, Target: binding.Target,
		Method: meta.Method, Path: path, RawURI: meta.RawURI, KeyID: key.ID, User: identity, HasUser: hasUser}
	until, err := h.config.Authorize(admission, call)
	if err != nil {
		reject(w, statusFor(err))
		return
	}
	if hasUser && identity.ExpiresAt.Before(until) {
		until = identity.ExpiresAt
	}
	if until.Before(deadline) {
		deadline = until
	}
	ctx, stop := context.WithDeadline(admission, deadline)
	defer stop()
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		reject(w, http.StatusServiceUnavailable)
		return
	}

	var expected *uint64
	if revision := fields.Get("X-Outgate-Expected-Route-Revision"); revision != "" {
		value, _ := strconv.ParseUint(revision, 10, 64) // verified canonical positive u64
		expected = &value
	}
	route := h.config.Routes.Lookup(meta.RawURI, binding.Target, expected)
	if route.Session == nil {
		status := route.Status
		if status == 0 {
			status = http.StatusServiceUnavailable
		}
		reject(w, status)
		return
	}
	if err := h.config.Routes.CanDispatchRoute(route, meta.RawURI); err != nil {
		reject(w, statusFor(err))
		return
	}
	recipient, err := h.config.Resolve(ctx, route)
	if err != nil {
		reject(w, statusFor(err))
		return
	}
	if recipient.Transport == nil || recipient.Transport.Handle() != route.Session ||
		subtle.ConstantTimeCompare(key.Secret, recipient.Key.Secret) == 1 {
		reject(w, http.StatusServiceUnavailable)
		return
	}
	if !recipient.ValidUntil.IsZero() && recipient.ValidUntil.Before(deadline) {
		deadline = recipient.ValidUntil
		var release context.CancelFunc
		ctx, release = context.WithDeadline(ctx, deadline)
		defer release()
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		reject(w, http.StatusServiceUnavailable)
		return
	}
	if err := h.config.Replay.Ready(ctx); err != nil {
		reject(w, http.StatusServiceUnavailable)
		return
	}
	// Prepare the egress signature before spending a nonce on a configuration
	// error. No I/O occurs here and the request body remains on the ingress.
	outgoing, err := h.outgoing(req, meta, route, recipient.Key)
	if err != nil {
		reject(w, http.StatusServiceUnavailable)
		return
	}
	if err := h.config.Routes.CanDispatchRoute(route, meta.RawURI); err != nil {
		reject(w, statusFor(err))
		return
	}
	if err := verified.Signature().Reserve(ctx, h.config.Replay, h.config.ReplayNamespace, time.Now()); err != nil {
		reject(w, statusFor(err))
		return
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		reject(w, http.StatusServiceUnavailable)
		return
	}
	if !verified.Signature().ValidAt(time.Now()) {
		reject(w, http.StatusUnauthorized)
		return
	}
	if h.config.Revalidate != nil {
		if err := h.config.Revalidate(ctx, call, key, route, recipient); err != nil {
			reject(w, statusFor(err))
			return
		}
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		reject(w, http.StatusServiceUnavailable)
		return
	}
	if err := h.config.Routes.CanDispatchRoute(route, meta.RawURI); err != nil {
		reject(w, statusFor(err))
		return
	}
	proxy := httputil.ReverseProxy{
		Transport: recipient.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL, pr.Out.Host, pr.Out.Header = outgoing.URL, outgoing.Host, outgoing.Header
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			reject(w, http.StatusBadGateway)
		},
	}
	if route.Session.Instance().RewriteMountHeaders {
		proxy.ModifyResponse = func(response *http.Response) error {
			if h.config.RewriteResponse != nil {
				return h.config.RewriteResponse(route, response)
			}
			return rewriteMountResponse(route.Prefix, meta.RawURI, response)
		}
	}
	response := http.NewResponseController(w)
	_ = response.SetReadDeadline(deadline)
	_ = response.SetWriteDeadline(deadline)
	proxy.ServeHTTP(w, req.WithContext(ctx))
}

func verifiedPeer(state *tls.ConnectionState, domain string, now time.Time) (Peer, bool) {
	if state == nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 ||
		len(state.VerifiedChains[0]) == 0 || len(state.PeerCertificates) == 0 {
		return Peer{}, false
	}
	cert := state.PeerCertificates[0]
	if cert == nil || !cert.Equal(state.VerifiedChains[0][0]) || cert.NotAfter.Sub(cert.NotBefore) > 24*time.Hour ||
		now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return Peer{}, false
	}
	var result Peer
	for _, uri := range cert.URIs {
		if uri.Scheme != "spiffe" || uri.Host != domain {
			continue
		}
		parts := strings.Split(uri.Path, "/")
		if result.Certificate != nil || uri.RawPath != "" || uri.User != nil || uri.Opaque != "" || uri.ForceQuery ||
			uri.RawQuery != "" || uri.Fragment != "" || uri.RawFragment != "" || len(parts) != 5 ||
			parts[0] != "" || parts[1] != "service" || parts[3] != "instance" ||
			!validID(parts[2], 64) || !validID(parts[4], 128) {
			return Peer{}, false
		}
		result = Peer{ServiceID: parts[2], InstanceID: parts[4], SPKI: sha256.Sum256(cert.RawSubjectPublicKeyInfo), Certificate: cert}
	}
	return result, result.Certificate != nil
}

func validID(id string, limit int) bool {
	if len(id) == 0 || len(id) > limit {
		return false
	}
	for i, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, delivery.ErrDelivery), errors.Is(err, httpsig.ErrAuth), errors.Is(err, httpsig.ErrReplay):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrRateLimited), errors.Is(err, httpsig.ErrReplayCallerQuota):
		return http.StatusTooManyRequests
	case errors.Is(err, registry.ErrRevisionConflict):
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}

func reject(w http.ResponseWriter, status int) {
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	if status == http.StatusConflict {
		w.Header().Set("X-Outgate-Error-Code", "route_revision_conflict")
	}
	http.Error(w, http.StatusText(status), status)
}
