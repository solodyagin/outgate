package tlsfiles

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixture struct {
	cert, key, ca []byte
	expiry        time.Time
}

func material(t *testing.T, mutate func(*x509.Certificate)) fixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"gateway.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mutate != nil {
		mutate(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), ca.NotAfter}
}
func write(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "material.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestLoad(t *testing.T) {
	f := material(t, nil)
	cp, kp := write(t, append(bytes.Clone(f.cert), f.ca...)), write(t, f.key)
	got, err := LoadServer(t.Context(), cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certificate.Certificate) != 2 || !got.ValidUntil.Equal(f.expiry) {
		t.Fatal("chain expiry not preserved")
	}
	roots, until, err := LoadRoots(t.Context(), write(t, f.ca))
	if err != nil || !until.Equal(f.expiry) {
		t.Fatal("roots", err)
	}
	if _, err := got.Certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "gateway.example"}); err != nil {
		t.Fatal(err)
	}
	// The snapshot owns decoded material; source files are no longer consulted.
	if err := os.Remove(cp); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(kp); err != nil {
		t.Fatal(err)
	}
	if _, err := got.Certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example"}); err == nil {
		t.Fatal("hostname bypass")
	}
}
func TestRejectServer(t *testing.T) {
	f := material(t, nil)
	other := material(t, nil)
	cases := map[string]fixture{
		"mismatch":    {f.cert, other.key, f.ca, f.expiry},
		"expired":     material(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }),
		"future":      material(t, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }),
		"client_only": material(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }),
		"no_sign":     material(t, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }),
		"ca_leaf":     material(t, func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true }),
		"critical": material(t, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}),
		"garbage":         {append([]byte("private info\n"), f.cert...), f.key, f.ca, f.expiry},
		"trailing":        {append(bytes.Clone(f.cert), []byte("secret data")...), f.key, f.ca, f.expiry},
		"key_trailing":    {f.cert, append(bytes.Clone(f.key), []byte("secret data")...), f.ca, f.expiry},
		"key_duplicate":   {f.cert, append(bytes.Clone(f.key), f.key...), f.ca, f.expiry},
		"duplicate_chain": {append(bytes.Clone(f.cert), f.cert...), f.key, f.ca, f.expiry},
		"wrong_chain":     {append(bytes.Clone(f.cert), other.ca...), f.key, f.ca, f.expiry},
		"reverse_chain":   {append(bytes.Clone(f.ca), f.cert...), f.key, f.ca, f.expiry},
		"empty":           {nil, f.key, f.ca, f.expiry},
		"oversized_cert":  {bytes.Repeat([]byte("x"), maxBundle+1), f.key, f.ca, f.expiry},
		"oversized_key":   {f.cert, bytes.Repeat([]byte("x"), maxKey+1), f.ca, f.expiry},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadServer(t.Context(), write(t, f.cert), write(t, f.key)); !errors.Is(err, ErrUnavailable) || err.Error() != ErrUnavailable.Error() {
				t.Fatalf("unsanitized failure: %v", err)
			}
		})
	}
}
func TestRootsAndLimits(t *testing.T) {
	f := material(t, nil)
	for name, data := range map[string][]byte{"leaf": f.cert, "duplicate": append(bytes.Clone(f.ca), f.ca...), "garbage": []byte("sensitive"), "trailing": append(bytes.Clone(f.ca), []byte("sensitive")...)} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := LoadRoots(t.Context(), write(t, data)); !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		})
	}
	if _, err := certificates(f.ca, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := certificates(append(bytes.Clone(f.cert), f.ca...), 1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("chain cap", err)
	}
	path := write(t, []byte("1234"))
	if _, err := read(t.Context(), path, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t.Context(), path, 3); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	for _, path := range []string{"", t.TempDir(), filepath.Join(t.TempDir(), "missing"), "bad\x00path"} {
		if _, err := read(t.Context(), path, 4); !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := LoadServer(ctx, "", ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := LoadRoots(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func FuzzCertificates(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxBundle {
			t.Skip()
		}
		certs, err := certificates(data, maxChain)
		if err == nil && (len(certs) == 0 || len(certs) > maxChain) {
			t.Fatal("unbounded chain")
		}
	})
}

func TestKeyAlgorithms(t *testing.T) {
	for _, name := range []string{"rsa", "weak_rsa", "ecdsa", "weak_ecdsa"} {
		t.Run(name, func(t *testing.T) {
			var key crypto.Signer
			var err error
			switch name {
			case "rsa":
				key, err = rsa.GenerateKey(rand.Reader, 2048)
			case "weak_rsa":
				key, err = rsa.GenerateKey(rand.Reader, 1024)
			case "ecdsa":
				key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			case "weak_ecdsa":
				key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			private, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = LoadServer(t.Context(), write(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), write(t, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})))
			if name == "weak_rsa" || name == "weak_ecdsa" {
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestSkippedMalformedPEM(t *testing.T) {
	f := material(t, nil)
	cert := append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), f.cert...)
	if _, err := LoadServer(t.Context(), write(t, cert), write(t, f.key)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	key := append([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n"), f.key...)
	if _, err := LoadServer(t.Context(), write(t, f.cert), write(t, key)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestRootSetMetadata(t *testing.T) {
	f := material(t, nil)
	set, err := LoadRootSet(t.Context(), write(t, f.ca))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Certificates) != 1 || set.Pool == nil || !set.ValidUntil.Equal(f.expiry) || !set.Certificates[0].NotAfter.Equal(f.expiry) {
		t.Fatal("missing trust metadata")
	}
	if _, err := LoadRootSet(t.Context(), write(t, f.cert)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
