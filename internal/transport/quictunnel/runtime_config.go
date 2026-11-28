package quictunnel

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
)

// RuntimeLimits reserve configured windows/buffers plus operator-measured
// connection overhead. These charges bound admission, not process RSS. Other
// ingress listeners need their own or a launcher-level shared budget.
type RuntimeLimits struct {
	MaxConnections, ConnectionsPerIP             int
	MaxHandshakes, HandshakesPerIP               int
	BufferBytes, BufferBytesPerService           int64
	ConnectionOverheadBytes                      int64
	StreamReceiveWindow, ConnectionReceiveWindow uint64
	HandshakeTimeout                             time.Duration // default/max 5s total, 2.5s idle
}

type SQLiteRuntimeConfig struct {
	Control                controlstate.Config
	Registry               registry.Config
	MinimumControlRevision uint64
	Replay                 replay.SQLiteConfig
	Certificate            tls.Certificate // key must remain read-only for runtime lifetime
	ClientRoots            *x509.CertPool
	// Owner and Security must be nil: the runtime binds its own stores and health.
	Admission DurableAdmissionConfig
	// AdditionalSecurity may only add dependency checks, never replace SQLite.
	// A successful assertion must expire within 5s; callbacks must honor context.
	AdditionalSecurity func(context.Context) (time.Time, error)
}

func runtimeTransport(limits RuntimeLimits, policy RegistrationPolicy) (*quic.Config, int64, error) {
	if limits.HandshakeTimeout == 0 {
		limits.HandshakeTimeout = 5 * time.Second
	}
	if limits.MaxConnections < 1 || limits.MaxConnections > 1000000 || limits.ConnectionsPerIP < 1 || limits.ConnectionsPerIP > limits.MaxConnections || limits.MaxHandshakes < 1 || limits.MaxHandshakes > limits.MaxConnections || limits.HandshakesPerIP < 1 || limits.HandshakesPerIP > limits.ConnectionsPerIP || limits.HandshakesPerIP > limits.MaxHandshakes || limits.ConnectionOverheadBytes < 1 || limits.ConnectionOverheadBytes > 1<<30 || limits.StreamReceiveWindow < 16384 || limits.StreamReceiveWindow > limits.ConnectionReceiveWindow || limits.ConnectionReceiveWindow > 16777216 || limits.HandshakeTimeout < 2*time.Millisecond || limits.HandshakeTimeout > 5*time.Second || policy.validate() != nil {
		return nil, 0, controlstate.ErrConfig
	}
	charge := int64(policy.Limits.BufferBytes) + int64(limits.ConnectionReceiveWindow) + limits.ConnectionOverheadBytes
	if limits.BufferBytes < charge || limits.BufferBytesPerService < charge || limits.BufferBytesPerService > limits.BufferBytes {
		return nil, 0, controlstate.ErrConfig
	}
	return &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: limits.HandshakeTimeout / 2, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second, InitialStreamReceiveWindow: limits.StreamReceiveWindow, MaxStreamReceiveWindow: limits.StreamReceiveWindow, InitialConnectionReceiveWindow: limits.ConnectionReceiveWindow, MaxConnectionReceiveWindow: limits.ConnectionReceiveWindow, MaxIncomingStreams: 1, MaxIncomingUniStreams: 3, Allow0RTT: false, EnableDatagrams: false}, charge, nil
}

func runtimeTLS(certificate tls.Certificate, roots *x509.CertPool) (*tls.Config, error) {
	if roots == nil || len(roots.Subjects()) == 0 || len(certificate.Certificate) < 1 || len(certificate.Certificate) > 16 {
		return nil, controlstate.ErrConfig
	}
	total := 0
	chain := make([][]byte, len(certificate.Certificate))
	for i, der := range certificate.Certificate {
		if len(der) == 0 || len(der) > 1<<20-total {
			return nil, controlstate.ErrConfig
		}
		total += len(der)
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, controlstate.ErrConfig
		}
		chain[i] = bytes.Clone(der)
	}
	switch key := certificate.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		if key == nil || key.D == nil || key.X == nil || key.Y == nil || key.Curve != elliptic.P256() && key.Curve != elliptic.P384() && key.Curve != elliptic.P521() || key.D.Sign() <= 0 || key.D.Cmp(key.Params().N) >= 0 {
			return nil, controlstate.ErrConfig
		}
		x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
		if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
			return nil, controlstate.ErrConfig
		}
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.D == nil || key.D.Sign() <= 0 || key.N.Sign() <= 0 || key.E < 3 || key.N.BitLen() > 8192 || key.Validate() != nil {
			return nil, controlstate.ErrConfig
		}
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
			return nil, controlstate.ErrConfig
		}
	default:
		return nil, controlstate.ErrConfig
	}
	leaf, err := x509.ParseCertificate(chain[0])
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if err != nil || !ok || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, controlstate.ErrConfig
	}
	if len(leaf.ExtKeyUsage) > 0 {
		serverUsage := false
		for _, usage := range leaf.ExtKeyUsage {
			serverUsage = serverUsage || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !serverUsage {
			return nil, controlstate.ErrConfig
		}
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return nil, controlstate.ErrConfig
	}
	// Copy only the static certificate/key pair. Dynamic TLS callbacks, session
	// tickets, arbitrary ALPN, 0-RTT and permissive client-auth cannot bypass policy.
	cert := tls.Certificate{Certificate: chain, PrivateKey: certificate.PrivateKey, Leaf: leaf}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots.Clone(), NextProtos: []string{v1.QUICALPN}, SessionTicketsDisabled: true}, nil
}
