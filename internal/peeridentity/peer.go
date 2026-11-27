// Package peeridentity reads service identity only from verified TLS state.
package peeridentity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"
	"time"
)

type Peer struct {
	ServiceID, InstanceID string
	SPKI                  [32]byte
	Certificate           *x509.Certificate // read-only verified leaf
}

func Read(state *tls.ConnectionState, domain string, now time.Time) (Peer, bool) {
	if state == nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 ||
		len(state.VerifiedChains[0]) == 0 || state.VerifiedChains[0][0] == nil || len(state.PeerCertificates) == 0 {
		return Peer{}, false
	}
	cert := state.PeerCertificates[0]
	if cert == nil || !cert.Equal(state.VerifiedChains[0][0]) || cert.NotAfter.Sub(cert.NotBefore) > 24*time.Hour ||
		now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return Peer{}, false
	}
	var result Peer
	for _, uri := range cert.URIs {
		if uri == nil {
			return Peer{}, false
		}
		if uri.Scheme != "spiffe" || uri.Host != domain {
			continue
		}
		parts := strings.Split(uri.Path, "/")
		if result.Certificate != nil || uri.RawPath != "" || uri.User != nil || uri.Opaque != "" || uri.ForceQuery ||
			uri.RawQuery != "" || uri.Fragment != "" || uri.RawFragment != "" || len(parts) != 5 ||
			parts[0] != "" || parts[1] != "service" || parts[3] != "instance" ||
			!ValidID(parts[2], 64) || !ValidID(parts[4], 128) {
			return Peer{}, false
		}
		result = Peer{ServiceID: parts[2], InstanceID: parts[4], SPKI: sha256.Sum256(cert.RawSubjectPublicKeyInfo), Certificate: cert}
	}
	return result, result.Certificate != nil
}

func ValidID(id string, limit int) bool {
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

func ValidTrustDomain(domain string) bool {
	authority, err := url.Parse("spiffe://" + domain)
	return err == nil && authority.Hostname() != "" && authority.Hostname() == domain && authority.String() == "spiffe://"+domain && !strings.ContainsAny(domain, ":[]")
}
