// Package tlsfiles loads bounded, static TLS material from deployment-controlled files.
package tlsfiles

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("outgate: TLS files unavailable or invalid")

const (
	maxBundle = 1 << 20
	maxKey    = 16 << 10
	maxChain  = 16
	maxRoots  = 64
)

// Server is a startup snapshot. Its private key must remain read-only while in use.
// ValidUntil is the earliest chain expiry; callers must enforce it at runtime.
type Server struct {
	Certificate tls.Certificate
	ValidUntil  time.Time
}

// LoadServer checks the pair, server usage, chain order/signatures and current
// validity. It does not establish trust in the server identity or check a hostname.
func LoadServer(ctx context.Context, certFile, keyFile string) (Server, error) {
	certPEM, err := read(ctx, certFile, maxBundle)
	if err != nil {
		return Server{}, err
	}
	keyPEM, err := read(ctx, keyFile, maxKey)
	if err != nil {
		return Server{}, err
	}
	defer clear(keyPEM)
	chain, err := certificates(certPEM, maxChain)
	if err != nil {
		return Server{}, err
	}
	block, rest := pem.Decode(keyPEM)
	if block != nil {
		defer clear(block.Bytes)
	}
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(keyPEM), []byte("-----BEGIN "+block.Type+"-----")) || bytes.Count(keyPEM, []byte("-----BEGIN ")) != 1 {
		return Server{}, ErrUnavailable
	}
	if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return Server{}, ErrUnavailable
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Server{}, ErrUnavailable
	}
	switch key := pair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.Validate() != nil {
			return Server{}, ErrUnavailable
		}
	case *ecdsa.PrivateKey:
		if key.Curve.Params().BitSize < 256 {
			return Server{}, ErrUnavailable
		}
	case ed25519.PrivateKey:
		if !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
			return Server{}, ErrUnavailable
		}
	default:
		return Server{}, ErrUnavailable
	}
	now := time.Now()
	until := chain[0].NotAfter
	for i, cert := range chain {
		if !valid(cert, now) {
			return Server{}, ErrUnavailable
		}
		if cert.NotAfter.Before(until) {
			until = cert.NotAfter
		}
		if i > 0 && chain[i-1].CheckSignatureFrom(cert) != nil {
			return Server{}, ErrUnavailable
		}
	}
	leaf := chain[0]
	if leaf.IsCA || leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Server{}, ErrUnavailable
	}
	if len(leaf.ExtKeyUsage) > 0 {
		allowed := false
		for _, usage := range leaf.ExtKeyUsage {
			allowed = allowed || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !allowed {
			return Server{}, ErrUnavailable
		}
	}
	if err := ctx.Err(); err != nil {
		return Server{}, err
	}
	pair.Leaf = leaf
	return Server{Certificate: pair, ValidUntil: until}, nil
}

// LoadRoots loads only explicitly configured CA certificates, never system roots.
// The returned deadline conservatively expires the whole snapshot when its first
// CA expires. Callers own the pool and must enforce that deadline.
func LoadRoots(ctx context.Context, path string) (*x509.CertPool, time.Time, error) {
	set, err := LoadRootSet(ctx, path)
	if err != nil {
		return nil, time.Time{}, err
	}
	return set.Pool, set.ValidUntil, nil
}

// RootSet retains the configured certificates for offline trust-separation checks.
// The caller owns the pool and certificates and must keep them read-only in use.
type RootSet struct {
	Pool         *x509.CertPool
	Certificates []*x509.Certificate
	ValidUntil   time.Time
}

func LoadRootSet(ctx context.Context, path string) (RootSet, error) {
	data, err := read(ctx, path, maxBundle)
	if err != nil {
		return RootSet{}, err
	}
	certs, err := certificates(data, maxRoots)
	if err != nil {
		return RootSet{}, err
	}
	pool := x509.NewCertPool()
	now, until := time.Now(), certs[0].NotAfter
	for _, cert := range certs {
		if !valid(cert, now) || !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return RootSet{}, ErrUnavailable
		}
		if cert.NotAfter.Before(until) {
			until = cert.NotAfter
		}
		pool.AddCert(cert)
	}
	if err := ctx.Err(); err != nil {
		return RootSet{}, err
	}
	return RootSet{Pool: pool, Certificates: certs, ValidUntil: until}, nil
}

func valid(cert *x509.Certificate, now time.Time) bool {
	return !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) && len(cert.UnhandledCriticalExtensions) == 0
}

func certificates(data []byte, limit int) ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	seen := make(map[string]bool)
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if len(result) == limit || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrUnavailable
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 || seen[string(block.Bytes)] || bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return nil, ErrUnavailable
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrUnavailable
		}
		seen[string(block.Bytes)] = true
		result = append(result, cert)
		data = rest
	}
	if len(result) == 0 {
		return nil, ErrUnavailable
	}
	return result, nil
}

func read(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(path) == 0 || len(path) > 4096 || strings.ContainsRune(path, 0) {
		return nil, ErrUnavailable
	}
	// Reject special files before open, then check descriptor identity/size.
	// This assumes operator-controlled local files, not an adversarial filesystem.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, ErrUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() < 1 || opened.Size() > limit {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != opened.Size() || int64(len(data)) > limit {
		clear(data)
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}
