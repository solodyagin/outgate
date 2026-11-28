package deployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	"github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/tlsfiles"
)

type ca struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	der  []byte
}

func newCA(t *testing.T, parent *ca, lifetime ...time.Duration) ca {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if len(lifetime) > 0 {
		template.NotAfter = time.Now().Add(lifetime[0])
	}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{cert, key, der}
}
func write(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "material.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func caFile(t *testing.T, root ca) string {
	return write(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.der}))
}
func serverFiles(t *testing.T, root ca) (string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"gateway.example.com", "tunnel.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, root.cert, pub, root.key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.der})...)
	return write(t, chain), write(t, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}
func obj(m map[string]any, key string) map[string]any { return m[key].(map[string]any) }
func document(t *testing.T, v map[string]any) *config.Document {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d, err := config.Parse(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func fixture(t *testing.T, caLifetime ...time.Duration) (*config.Document, map[string]any) {
	t.Helper()
	data, err := os.ReadFile("../../docs/examples/gateway.production.yaml")
	if err != nil {
		t.Fatal(err)
	}
	base, err := config.Parse(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	v := base.Values()
	obj(obj(v, "tunnel"), "wss")["enabled"] = false
	root, admin := newCA(t, nil, caLifetime...), newCA(t, nil)
	cert, key := serverFiles(t, root)
	for _, section := range []string{"tunnel", "interservice"} {
		tls := obj(obj(v, section), "tls")
		tls["cert_file"] = cert
		tls["key_file"] = key
	}
	serviceCA := caFile(t, root)
	obj(v, "auth")["service_ca_file"] = serviceCA
	obj(obj(v, "interservice"), "tls")["client_ca_file"] = serviceCA
	obj(obj(v, "admin"), "tls")["client_ca_file"] = caFile(t, admin)
	caller := obj(obj(obj(v, "interservice"), "callers"), "my-service")["keys"].([]any)[0].(map[string]any)
	caller["secret_env"] = "DEPLOYMENT_TEST_CALL_KEY"
	t.Setenv("DEPLOYMENT_TEST_CALL_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	recipient := obj(obj(obj(v, "interservice"), "recipients"), "reports-service")["keys"].([]any)[0].(map[string]any)
	recipient["secret_file"] = write(t, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))))
	return document(t, v), v
}
func load(t *testing.T, doc *config.Document) *SharedSources {
	t.Helper()
	p, err := PlanSharedSecurity(doc, time.Now().Add(time.Hour), []string{"tunnel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func TestSharedSources(t *testing.T) {
	doc, v := fixture(t)
	s := load(t, doc)
	base, err := s.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if base.Tunnel.Admission.TrustDomain != "outgate.example" || base.Tunnel.ClientRoots == nil || base.Tunnel.Certificate.Leaf.VerifyHostname("gateway.example.com") != nil || base.RecipientKeyIDs["reports-service"] != "gateway-reports-1" || base.State.Callers["my-service"].PerSecond != 100 || base.Service.AllowedAuthorities[0] != "gateway.example.com:9443" {
		t.Fatal("incomplete mapping")
	}
	until, err := base.KeyHealth(t.Context())
	if err != nil || !until.After(time.Now()) || until.After(time.Now().Add(5*time.Second)) {
		t.Fatal(until, err)
	}
	for _, test := range []struct{ leg, service, id string }{{httpsig.Call, "my-service", "my-call-1"}, {httpsig.Gateway, "reports-service", "gateway-reports-1"}} {
		got, err := base.State.Keys(t.Context(), test.leg, test.service, test.id)
		if err != nil || got.NotAfter.After(s.until) {
			t.Fatal(got.NotAfter, err)
		}
	}
	if _, err := base.State.Keys(t.Context(), httpsig.Gateway, "my-service", "my-call-1"); err == nil {
		t.Fatal("cross-leg bypass")
	}
	// Remove inputs after loading: this source is the immutable local authority.
	for _, path := range []string{obj(obj(v, "tunnel"), "tls")["cert_file"].(string), obj(obj(v, "tunnel"), "tls")["key_file"].(string), obj(v, "auth")["service_ca_file"].(string)} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DEPLOYMENT_TEST_CALL_KEY", "replaced")
	if _, err := base.KeyHealth(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Detached certificate DER, key, roots, maps and authority lists for each bind.
	again, err := s.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	base.Tunnel.Certificate.Certificate[0][0] ^= 1
	base.Tunnel.Certificate.PrivateKey.(ed25519.PrivateKey)[0] ^= 1
	base.RecipientKeyIDs["reports-service"] = "changed"
	base.State.Callers["my-service"] = struct{ PerSecond, Burst int }{1, 1}
	base.Service.AllowedAuthorities[0] = "changed"
	if again.Tunnel.Certificate.Certificate[0][0] != s.cert.Certificate[0][0] || bytes.Equal(base.Tunnel.Certificate.PrivateKey.(ed25519.PrivateKey), again.Tunnel.Certificate.PrivateKey.(ed25519.PrivateKey)) || again.RecipientKeyIDs["reports-service"] == "changed" || again.Service.AllowedAuthorities[0] == "changed" {
		t.Fatal("mutable bindings")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, s); strings.Contains(got, "pem") || strings.Contains(got, "PRIVATE") {
			t.Fatal("format leaked")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := base.KeyHealth(t.Context()); !errors.Is(err, ErrSources) {
		t.Fatal(err)
	}
	if _, err := base.State.Keys(t.Context(), httpsig.Call, "my-service", "my-call-1"); !errors.Is(err, ErrSources) {
		t.Fatal(err)
	}
	if _, err := s.Bind(gateway.Config{}); !errors.Is(err, ErrSources) {
		t.Fatal(err)
	}
}
func TestRejectedProfiles(t *testing.T) {
	doc, _ := fixture(t)
	for _, names := range [][]string{nil, {"*.example.com"}, {"tunnel.example.com:7171"}, {"https://example.com"}, {"a%00b"}} {
		if _, err := PlanSharedSecurity(doc, time.Now().Add(time.Hour), names); !errors.Is(err, ErrProfile) {
			t.Fatal(err)
		}
	}
	for name, change := range map[string]func(map[string]any){
		"wss": func(v map[string]any) { obj(obj(v, "tunnel"), "wss")["enabled"] = true },
		"quic_disabled": func(v map[string]any) {
			obj(obj(v, "tunnel"), "quic")["enabled"] = false
			obj(obj(v, "tunnel"), "wss")["enabled"] = true
		},
		"rate": func(v map[string]any) { obj(v, "interservice")["caller_rate_per_second"] = 1000001 },
	} {
		t.Run(name, func(t *testing.T) {
			values := doc.Values()
			change(values)
			if _, err := PlanSharedSecurity(document(t, values), time.Now().Add(time.Hour), []string{"tunnel.example.com"}); !errors.Is(err, ErrProfile) {
				t.Fatal(err)
			}
		})
	}
	if _, err := PlanSharedSecurity(doc, time.Time{}, []string{"tunnel.example.com"}); !errors.Is(err, ErrProfile) {
		t.Fatal(err)
	}
}
func TestRejectedSources(t *testing.T) {
	for _, fault := range []string{"hostname", "service_hostname", "pair", "service_roots", "admin_roots", "missing_key", "missing_secret"} {
		t.Run(fault, func(t *testing.T) {
			doc, v := fixture(t)
			names := []string{"tunnel.example.com"}
			want := ErrSources
			switch fault {
			case "hostname":
				names = []string{"other.example.com"}
			case "service_hostname":
				obj(v, "interservice")["allowed_authorities"] = []any{"other.example.com:9443"}
			case "pair":
				cert, key := serverFiles(t, newCA(t, nil))
				obj(obj(v, "interservice"), "tls")["cert_file"] = cert
				obj(obj(v, "interservice"), "tls")["key_file"] = key
				want = ErrProfile
			case "service_roots":
				obj(obj(v, "interservice"), "tls")["client_ca_file"] = caFile(t, newCA(t, nil))
				want = ErrProfile
			case "admin_roots":
				obj(obj(v, "admin"), "tls")["client_ca_file"] = obj(v, "auth")["service_ca_file"]
			case "missing_key":
				obj(obj(v, "tunnel"), "tls")["key_file"] = "sensitive-missing-file.pem"
			case "missing_secret":
				t.Setenv("DEPLOYMENT_TEST_CALL_KEY", "")
			}
			if fault != "hostname" {
				doc = document(t, v)
			}
			p, err := PlanSharedSecurity(doc, time.Now().Add(time.Hour), names)
			if err != nil {
				t.Fatal(err)
			}
			s, err := p.Load(t.Context())
			if s != nil || !errors.Is(err, want) || err.Error() != want.Error() {
				t.Fatalf("sources=%v error=%v", s, err)
			}
		})
	}
}
func TestCASeparation(t *testing.T) {
	admin := newCA(t, nil)
	service := newCA(t, &admin)
	set := func(root ca) tlsfiles.RootSet {
		p := x509.NewCertPool()
		p.AddCert(root.cert)
		return tlsfiles.RootSet{Pool: p, Certificates: []*x509.Certificate{root.cert}, ValidUntil: root.cert.NotAfter}
	}
	if separate(set(service), set(admin)) || separate(set(admin), set(service)) {
		t.Fatal("cross-signed roles accepted")
	}
	different := newCA(t, nil)
	if !separate(set(different), set(admin)) {
		t.Fatal("independent roots rejected")
	}
	reissued := *admin.cert
	reissued.SerialNumber = big.NewInt(99)
	der, err := x509.CreateCertificate(rand.Reader, &reissued, &reissued, admin.key.Public(), admin.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if separate(set(ca{cert: cert, key: admin.key, der: der}), set(admin)) {
		t.Fatal("same SPKI reissue accepted")
	}
}
func TestLifecycle(t *testing.T) {
	doc, _ := fixture(t)
	deadline := time.Now().Add(time.Second)
	p, err := PlanSharedSecurity(doc, deadline, []string{"tunnel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bound, err := s.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := bound.State.Keys(t.Context(), httpsig.Call, "my-service", "my-call-1")
	if err != nil || !got.NotAfter.Equal(deadline) {
		t.Fatal(got.NotAfter, err)
	}
	until, err := bound.KeyHealth(t.Context())
	if err != nil || !until.Equal(deadline) {
		t.Fatal(until, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Health(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := p.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(deadline) + time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if _, err := bound.KeyHealth(t.Context()); !errors.Is(err, ErrSources) {
		t.Fatal(err)
	}
	if _, err := bound.State.Keys(t.Context(), httpsig.Call, "my-service", "my-call-1"); !errors.Is(err, ErrSources) {
		t.Fatal(err)
	}
}
func TestConcurrentClose(t *testing.T) {
	doc, _ := fixture(t)
	s := load(t, doc)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				_, _ = s.Health(t.Context())
				_, _ = s.Bind(gateway.Config{})
				_, _ = s.keys(t.Context(), httpsig.Call, "my-service", "my-call-1")
			}
		})
	}
	wg.Go(func() { _ = s.Close() })
	wg.Wait()
}

func TestRejectOverridesAndZeroValues(t *testing.T) {
	doc, _ := fixture(t)
	s := load(t, doc)
	valid, err := s.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*gateway.Config){
		func(c *gateway.Config) { c.KeyHealth = valid.KeyHealth },
		func(c *gateway.Config) { c.State.Keys = valid.State.Keys },
		func(c *gateway.Config) { c.State.Callers = valid.State.Callers },
		func(c *gateway.Config) { c.Tunnel.Certificate = valid.Tunnel.Certificate },
		func(c *gateway.Config) { c.Tunnel.ClientRoots = valid.Tunnel.ClientRoots },
		func(c *gateway.Config) { c.Tunnel.Admission.TrustDomain = "other.example" },
		func(c *gateway.Config) { c.Service.AllowedAuthorities = []string{"other.example"} },
		func(c *gateway.Config) { c.Service.Certificate = valid.Tunnel.Certificate },
		func(c *gateway.Config) { c.RecipientKeyIDs = valid.RecipientKeyIDs },
	} {
		c := gateway.Config{}
		change(&c)
		if _, err := s.Bind(c); !errors.Is(err, ErrProfile) {
			t.Fatal("override accepted", err)
		}
	}
	var zero SharedSources
	if _, err := zero.Health(t.Context()); !errors.Is(err, ErrSources) {
		t.Fatal(err)
	}
	if err := zero.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := zero.Bind(gateway.Config{}); !errors.Is(err, ErrSources) {
		t.Fatal(err)
	}
	if _, err := (*SharedSecurityPlan)(nil).Load(t.Context()); !errors.Is(err, ErrProfile) {
		t.Fatal(err)
	}
}

func TestCALifetimeCapsAllCallbacks(t *testing.T) {
	doc, _ := fixture(t, 10*time.Minute)
	s := load(t, doc)
	root, err := x509.ParseCertificate(s.cert.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if !s.until.Equal(root.NotAfter) || !s.until.Before(s.cert.Leaf.NotAfter) {
		t.Fatal("CA expiry ignored")
	}
	bound, err := s.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := bound.State.Keys(t.Context(), httpsig.Call, "my-service", "my-call-1")
	if err != nil || !accepted.NotAfter.Equal(root.NotAfter) {
		t.Fatal("key lifetime exceeded CA", accepted.NotAfter, err)
	}
}

func TestPlanningModeDefaultsAndPorts(t *testing.T) {
	data, err := os.ReadFile("../../docs/examples/gateway.development.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dev, err := config.Parse(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanSharedSecurity(dev, time.Now().Add(time.Hour), []string{"tunnel.example.com"}); !errors.Is(err, ErrProfile) {
		t.Fatal("development fallback", err)
	}
	doc, v := fixture(t)
	delete(obj(obj(v, "tunnel"), "quic"), "enabled")
	delete(obj(v, "interservice"), "caller_rate_per_second")
	delete(obj(v, "interservice"), "caller_burst")
	if _, err := PlanSharedSecurity(document(t, v), time.Now().Add(time.Hour), []string{"tunnel.example.com"}); err != nil {
		t.Fatal("missing QUIC default", err)
	}
	p, err := PlanSharedSecurity(document(t, v), time.Now().Add(time.Hour), []string{"tunnel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := p.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	bound, err := sources.Bind(gateway.Config{})
	if err != nil || bound.State.Callers["my-service"].PerSecond != 100 || bound.State.Callers["my-service"].Burst != 200 {
		t.Fatal("caller defaults", err)
	}
	v = doc.Values()
	obj(v, "interservice")["allowed_authorities"] = []any{"gateway.example.com:99999"}
	if _, err := PlanSharedSecurity(document(t, v), time.Now().Add(time.Hour), []string{"tunnel.example.com"}); !errors.Is(err, ErrProfile) {
		t.Fatal("invalid authority port", err)
	}
}
