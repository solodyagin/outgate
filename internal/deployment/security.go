// Package deployment maps validated deployment inputs into runtime components.
package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/keyring"
	"github.com/solodyagin/outgate/internal/peeridentity"
	"github.com/solodyagin/outgate/internal/servicecall"
	"github.com/solodyagin/outgate/internal/tlsfiles"
)

var (
	ErrProfile = errors.New("outgate: unsupported shared security profile")
	ErrSources = errors.New("outgate: deployment security sources unavailable")
)

type pairFiles struct {
	Cert string `json:"cert_file"`
	Key  string `json:"key_file"`
	CA   string `json:"client_ca_file"`
}

// This projection deliberately covers only shared ingress security. It is not a
// complete launch configuration and never authorizes ignoring other YAML fields.
type securityInput struct {
	Tunnel struct {
		TLS  pairFiles
		QUIC struct{ Enabled *bool }
		WSS  struct{ Enabled bool }
	}
	Interservice struct {
		TLS         pairFiles
		Authorities []string          `json:"allowed_authorities"`
		Headers     map[string]string `json:"trusted_attributes"`
		Rate        int               `json:"caller_rate_per_second"`
		Burst       int               `json:"caller_burst"`
	}
	Auth struct {
		CA     string `json:"service_ca_file"`
		Domain string `json:"service_trust_domain"`
	}
	Admin struct{ TLS pairFiles }
}

// SharedSecurityPlan owns detached references for the currently supported
// production QUIC + signed HTTPS shared identity. No IO occurs during planning.
// The plan does not cover browser/Admin listeners, stores, JWT or process budgets.
type SharedSecurityPlan struct {
	input securityInput
	names []string
	keys  keyring.Config
}

func (*SharedSecurityPlan) String() string     { return "outgate shared security plan (redacted)" }
func (p *SharedSecurityPlan) GoString() string { return p.String() }

// PlanSharedSecurity requires explicit tunnel DNS/IP identities because a bind
// address does not specify the hostname clients verify. Service names come from
// the configured exact allowed_authorities. No DNS resolution is performed.
func PlanSharedSecurity(doc *config.Document, notAfter time.Time, tunnelNames []string) (*SharedSecurityPlan, error) {
	if doc == nil || doc.Mode() != "production" || !notAfter.After(time.Now()) || len(tunnelNames) == 0 || len(tunnelNames) > 64 {
		return nil, ErrProfile
	}
	p := &SharedSecurityPlan{names: slices.Clone(tunnelNames)}
	// Materialize the defaults for fields owned by this security projection.
	p.input.Interservice.Rate = 100
	p.input.Interservice.Burst = 200
	for _, name := range p.names {
		if !validName(name) {
			return nil, ErrProfile
		}
	}
	data, err := json.Marshal(doc.Values())
	if err != nil {
		return nil, ErrProfile
	}
	defer clear(data)
	if err := json.Unmarshal(data, &p.input); err != nil {
		return nil, ErrProfile
	}
	in := p.input
	if in.Tunnel.QUIC.Enabled != nil && !*in.Tunnel.QUIC.Enabled || in.Tunnel.WSS.Enabled || len(in.Interservice.Authorities) == 0 || len(in.Interservice.Authorities) > 256 || !peeridentity.ValidTrustDomain(in.Auth.Domain) {
		return nil, ErrProfile
	}
	if in.Interservice.Rate < 1 || in.Interservice.Rate > 1000000 || in.Interservice.Burst < 1 || in.Interservice.Burst > 1000000 {
		return nil, ErrProfile
	}
	for _, a := range in.Interservice.Authorities {
		if !validName(authorityName(a)) {
			return nil, ErrProfile
		}
	}
	p.keys, err = doc.KeyringConfig(notAfter)
	if err != nil {
		return nil, ErrProfile
	}
	if len(p.keys.Callers) == 0 || len(p.keys.Recipients) == 0 {
		return nil, ErrProfile
	}
	return p, nil
}
func authorityName(a string) string {
	if host, port, err := net.SplitHostPort(a); err == nil {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ""
		}
		return host
	}
	return strings.Trim(a, "[]")
}
func validName(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.TrimSpace(s) != s || strings.ContainsAny(s, "/\\%*?#@\x00") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// SharedSources owns the startup keyring and TLS snapshot. Close only after all
// runtime users actually finish, including cleanup following a timed-out shutdown.
// Health describes this local immutable authority, not external source freshness.
type SharedSources struct {
	mu          sync.RWMutex
	ring        *keyring.Ring
	cert        tls.Certificate
	roots       *x509.CertPool
	domain      string
	authorities []string
	headers     map[string]string
	callers     map[string]servicecall.CallerLimit
	until       time.Time
	closed      bool
}

func (*SharedSources) String() string     { return "outgate shared security sources (redacted)" }
func (s *SharedSources) GoString() string { return s.String() }

func (p *SharedSecurityPlan) Load(ctx context.Context) (*SharedSources, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil || p.input.Auth.Domain == "" || !p.keys.NotAfter.After(time.Now()) {
		return nil, ErrProfile
	}
	in := p.input
	tunnel, err := tlsfiles.LoadServer(ctx, in.Tunnel.TLS.Cert, in.Tunnel.TLS.Key)
	if err != nil {
		return nil, safeError(ctx)
	}
	service, err := tlsfiles.LoadServer(ctx, in.Interservice.TLS.Cert, in.Interservice.TLS.Key)
	if err != nil {
		return nil, safeError(ctx)
	}
	if !sameChain(tunnel.Certificate, service.Certificate) {
		return nil, ErrProfile
	}
	for _, name := range p.names {
		if tunnel.Certificate.Leaf.VerifyHostname(name) != nil {
			return nil, ErrSources
		}
	}
	for _, a := range in.Interservice.Authorities {
		if service.Certificate.Leaf.VerifyHostname(authorityName(a)) != nil {
			return nil, ErrSources
		}
	}
	roots, err := tlsfiles.LoadRootSet(ctx, in.Auth.CA)
	if err != nil {
		return nil, safeError(ctx)
	}
	serviceRoots, err := tlsfiles.LoadRootSet(ctx, in.Interservice.TLS.CA)
	if err != nil {
		return nil, safeError(ctx)
	}
	if !roots.Pool.Equal(serviceRoots.Pool) {
		return nil, ErrProfile
	}
	admin, err := tlsfiles.LoadRootSet(ctx, in.Admin.TLS.CA)
	if err != nil {
		return nil, safeError(ctx)
	}
	if !separate(roots, admin) {
		return nil, ErrSources
	}
	until := p.keys.NotAfter
	for _, expiry := range []time.Time{tunnel.ValidUntil, service.ValidUntil, roots.ValidUntil, serviceRoots.ValidUntil, admin.ValidUntil} {
		if expiry.Before(until) {
			until = expiry
		}
	}
	keys := p.keys
	keys.NotAfter = until
	ring, err := keyring.Load(ctx, keys)
	if err != nil {
		return nil, safeError(ctx)
	}
	s := &SharedSources{ring: ring, cert: tunnel.Certificate, roots: roots.Pool, domain: in.Auth.Domain, authorities: slices.Clone(in.Interservice.Authorities), headers: in.Interservice.Headers, until: until, callers: map[string]servicecall.CallerLimit{}}
	for id := range keys.Callers {
		s.callers[id] = servicecall.CallerLimit{PerSecond: in.Interservice.Rate, Burst: in.Interservice.Burst}
	}
	if _, err := s.Health(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}
func safeError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrSources
}
func sameChain(a, b tls.Certificate) bool {
	if len(a.Certificate) != len(b.Certificate) {
		return false
	}
	for i := range a.Certificate {
		if !bytes.Equal(a.Certificate[i], b.Certificate[i]) {
			return false
		}
	}
	return true
}
func separate(a, b tlsfiles.RootSet) bool {
	for _, left := range a.Certificates {
		for _, right := range b.Certificates {
			if sha256.Sum256(left.RawSubjectPublicKeyInfo) == sha256.Sum256(right.RawSubjectPublicKeyInfo) {
				return false
			}
		}
	}
	// Detect cross-signing paths provided by either configured bundle. Network
	// intermediates/AIA and unknown external PKI paths are deliberately not fetched.
	intermediates := x509.NewCertPool()
	for _, set := range []tlsfiles.RootSet{a, b} {
		for _, cert := range set.Certificates {
			intermediates.AddCert(cert)
		}
	}
	trusted := func(from, to tlsfiles.RootSet) bool {
		for _, cert := range from.Certificates {
			if _, err := cert.Verify(x509.VerifyOptions{Roots: to.Pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
				return true
			}
		}
		return false
	}
	return !trusted(a, b) && !trusted(b, a)
}

func (s *SharedSources) Health(ctx context.Context) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if s == nil {
		return time.Time{}, ErrSources
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.ring == nil || !s.until.After(time.Now()) {
		return time.Time{}, ErrSources
	}
	until, err := s.ring.Health(ctx)
	if err != nil {
		return time.Time{}, safeError(ctx)
	}
	if s.until.Before(until) {
		until = s.until
	}
	return until, nil
}
func (s *SharedSources) keys(ctx context.Context, leg, service, id string) (servicecall.AcceptedKey, error) {
	if _, err := s.Health(ctx); err != nil {
		return servicecall.AcceptedKey{}, err
	}
	return s.ring.Keys(ctx, leg, service, id)
}
func (s *SharedSources) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		if s.ring != nil {
			_ = s.ring.Close()
		}
		s.cert = tls.Certificate{}
		s.roots = nil
	}
	return nil
}

// Bind fills only the shared security fields in an otherwise caller-composed
// runtime config. Existing overrides are rejected. It neither opens the runtime
// nor validates the rest of deployment YAML or runtime settings.
func (s *SharedSources) Bind(base gateway.Config) (gateway.Config, error) {
	if s == nil {
		return gateway.Config{}, ErrSources
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.ring == nil || !s.until.After(time.Now()) {
		return gateway.Config{}, ErrSources
	}
	if !emptyCertificate(base.Tunnel.Certificate) || !emptyCertificate(base.Service.Certificate) || base.Service.ClientRoots != nil || base.Service.TrustDomain != "" || base.Tunnel.ClientRoots != nil || base.Tunnel.Admission.TrustDomain != "" || base.State.Keys != nil || base.State.Callers != nil || base.KeyHealth != nil || base.RecipientKeyIDs != nil || len(base.Service.AllowedAuthorities) != 0 || base.Service.AttributeHeaders != nil {
		return gateway.Config{}, ErrProfile
	}
	cert, err := cloneCertificate(s.cert)
	if err != nil {
		return gateway.Config{}, ErrSources
	}
	base.Tunnel.Certificate = cert
	base.Tunnel.ClientRoots = s.roots.Clone()
	base.Tunnel.Admission.TrustDomain = s.domain
	base.State.Keys = s.keys
	base.State.Callers = map[string]servicecall.CallerLimit{}
	for id, limit := range s.callers {
		base.State.Callers[id] = limit
	}
	base.KeyHealth = s.Health
	base.RecipientKeyIDs = s.ring.RecipientKeyIDs()
	base.Service.AllowedAuthorities = slices.Clone(s.authorities)
	base.Service.AttributeHeaders = map[string]string{}
	for k, v := range s.headers {
		base.Service.AttributeHeaders[k] = v
	}
	return base, nil
}
func cloneCertificate(cert tls.Certificate) (tls.Certificate, error) {
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(key)
	private, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	result := tls.Certificate{PrivateKey: private, Certificate: make([][]byte, len(cert.Certificate))}
	for i, der := range cert.Certificate {
		result.Certificate[i] = bytes.Clone(der)
	}
	result.Leaf, err = x509.ParseCertificate(result.Certificate[0])
	return result, err
}

func emptyCertificate(c tls.Certificate) bool {
	return c.PrivateKey == nil && len(c.Certificate) == 0 && c.Leaf == nil && len(c.SupportedSignatureAlgorithms) == 0 && len(c.OCSPStaple) == 0 && len(c.SignedCertificateTimestamps) == 0
}
