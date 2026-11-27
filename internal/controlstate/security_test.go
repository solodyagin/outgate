package controlstate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func securityConfig(t *testing.T) Config {
	c := configuration(t)
	c.Services = map[string][]string{"reports": {"/api"}, "sender": {"/sender"}, "other": {"/other"}, "frontend": {"/"}}
	c.RootFrontend = "frontend"
	return c
}
func change(t *testing.T, revision uint64) Change {
	c := command(t, Target{Kind: "service", ServiceID: "reports"}, revision)
	return Change{OperationID: c.OperationID, Actor: c.Actor, ExpectedRevision: c.ExpectedRevision, Reason: c.Reason}
}
func binding() GrantBinding {
	return GrantBinding{ServiceID: "reports", InstanceID: "reports-1", Version: "1.0.0", Paths: []string{"/api/v1", "/api/v2"}, Mounts: map[string]string{"api": "/api/v1"}, PathMode: "strip", RewriteMountHeaders: true, SPKI: strings.Repeat("a", 64), ArtifactDigest: "sha256:" + strings.Repeat("b", 64), ExpiresAt: time.Now().Add(10 * time.Minute).UTC(), CredentialGeneration: 7}
}
func peer() GrantPeer {
	return GrantPeer{ServiceID: "reports", InstanceID: "reports-1", SPKI: strings.Repeat("a", 64), CertificateSerial: "71ab"}
}
func registration(b GrantBinding) v1.Register {
	capabilities := append(v1.BaselineCapabilities(), "mount_discovery", "credential_generation")
	generation := v1.U64(b.CredentialGeneration)
	return v1.Register{Type: "register", ProtocolVersion: 1, ProtocolMinor: 1, Capabilities: capabilities, RequiredCapabilities: capabilities, ServiceID: b.ServiceID, InstanceID: b.InstanceID, Version: b.Version, Paths: append([]string{}, b.Paths...), Mounts: b.Mounts, PathMode: b.PathMode, RewriteMountHeaders: b.RewriteMountHeaders, CredentialGeneration: &generation, MaxConcurrentRequests: 4}
}
func accessRules() AccessSnapshot {
	return AccessSnapshot{Policies: []AccessPolicy{{Caller: "sender", Target: "reports", Paths: []string{"/api/v2", "/api/v1"}, Methods: []string{"POST", "GET"}, AllowBackground: true}}, InternalOnly: []InternalOnly{{Target: "reports", Paths: []string{"/api/v1/internal"}, Methods: []string{"POST"}, Callers: []string{"sender"}}}}
}

func TestGrantSecretOnceBindingAndRestart(t *testing.T) {
	config := securityConfig(t)
	s := fixture(t, config)
	b := binding()
	c := change(t, 1)
	issued, err := s.IssueGrant(t.Context(), c, b)
	must(t, err)
	if issued.DeploymentGrant == "" || issued.Record.Revision != 2 {
		t.Fatal("grant not issued")
	}
	id, secret, _ := strings.Cut(issued.DeploymentGrant, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	must(t, err)
	if len(decoded) != 32 || id != issued.Record.GrantID {
		t.Fatal("invalid credential entropy/ID")
	}
	var hash []byte
	must(t, s.db.QueryRowContext(t.Context(), "SELECT secret_hash FROM deployment_grants WHERE id=?", id).Scan(&hash))
	digest := sha256.Sum256(decoded)
	if string(hash) != string(digest[:]) {
		t.Fatal("digest did not cover decoded secret")
	}
	// Safe database surfaces must contain neither plaintext secret nor digest.
	for _, query := range []string{"SELECT record FROM deployment_grants", "SELECT result FROM security_results", "SELECT payload FROM control_outbox"} {
		var data []byte
		must(t, s.db.QueryRowContext(t.Context(), query).Scan(&data))
		if strings.Contains(string(data), secret) || strings.Contains(string(data), fmtDigest(digest)) || strings.Contains(string(data), "secret_hash") {
			t.Fatal("safe metadata contains credential material")
		}
	}
	reg := registration(b)
	reg.Paths = []string{"/api/v2", "/api/v1"}
	verified, err := s.VerifyDeploymentGrant(t.Context(), issued.DeploymentGrant, peer(), reg)
	must(t, err)
	if verified.GrantID != id {
		t.Fatal("wrong grant selected")
	}
	// Equivalent set order must deduplicate, not issue a second credential.
	b.Paths = []string{"/api/v2", "/api/v1"}
	repeated, err := s.IssueGrant(t.Context(), c, b)
	must(t, err)
	if repeated.DeploymentGrant != "" || !reflect.DeepEqual(repeated.Record, issued.Record) {
		t.Fatal("retry exposed secret or changed metadata")
	}
	for _, modify := range []func(*v1.Register){
		func(r *v1.Register) { r.Version = "other" }, func(r *v1.Register) { r.Paths = []string{"/api/v1"} }, func(r *v1.Register) { r.Mounts = map[string]string{"other": "/api/v1"} }, func(r *v1.Register) { r.PathMode = "preserve"; r.RewriteMountHeaders = false }, func(r *v1.Register) { g := v1.U64(8); r.CredentialGeneration = &g },
	} {
		wrong := reg
		modify(&wrong)
		if _, err := s.VerifyDeploymentGrant(t.Context(), issued.DeploymentGrant, peer(), wrong); !errors.Is(err, ErrDenied) {
			t.Fatal("changed binding accepted", err)
		}
	}
	if _, err := s.VerifyDeploymentGrant(t.Context(), id+"."+base64.RawURLEncoding.EncodeToString(make([]byte, 32)), peer(), reg); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong secret accepted", err)
	}
	wrongPeer := peer()
	wrongPeer.InstanceID = "reports-2"
	if _, err := s.GrantForPeer(t.Context(), id, wrongPeer); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign peer accepted", err)
	}
	must(t, s.Close())
	reopened, err := Open(t.Context(), config)
	must(t, err)
	defer reopened.Close()
	repeated, err = reopened.IssueGrant(t.Context(), c, b)
	must(t, err)
	if repeated.DeploymentGrant != "" {
		t.Fatal("restart restored secret")
	}
	_, err = reopened.VerifyDeploymentGrant(t.Context(), issued.DeploymentGrant, peer(), reg)
	must(t, err)
	events, err := reopened.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 1 || events[0].Action != "grant_issued" || events[0].Target.Value != id || events[0].OccurredAt.IsZero() {
		t.Fatal("grant audit missing", events)
	}
}

func TestGrantRevocationsAndExpiry(t *testing.T) {
	for _, kind := range []string{"service", "grant_id", "spki_sha256", "certificate_serial"} {
		t.Run(kind, func(t *testing.T) {
			s := fixture(t, securityConfig(t))
			b := binding()
			issued, err := s.IssueGrant(t.Context(), change(t, 1), b)
			must(t, err)
			target := Target{Kind: kind, ServiceID: "reports"}
			switch kind {
			case "grant_id":
				target.Value = issued.Record.GrantID
			case "spki_sha256":
				target.Value = b.SPKI
			case "certificate_serial":
				target.Value = peer().CertificateSerial
			}
			_, err = s.Revoke(t.Context(), command(t, target, 2))
			must(t, err)
			if _, err := s.GrantForPeer(t.Context(), issued.Record.GrantID, peer()); !errors.Is(err, ErrDenied) {
				t.Fatal("revoked peer accepted", err)
			}
		})
	}
	s := fixture(t, securityConfig(t))
	b := binding()
	c := change(t, 1)
	issued, err := s.IssueGrant(t.Context(), c, b)
	must(t, err)
	// Move the complete persisted lifetime into the past without sleeping.
	stored := issued.Record
	stored.IssuedAt = time.Now().Add(-time.Hour)
	stored.ExpiresAt = stored.IssuedAt.Add(time.Minute)
	data, err := json.Marshal(stored)
	must(t, err)
	_, err = s.db.ExecContext(t.Context(), "UPDATE deployment_grants SET record=?", data)
	must(t, err)
	if _, err := s.GrantForPeer(t.Context(), stored.GrantID, peer()); !errors.Is(err, ErrDenied) {
		t.Fatal("expired grant accepted", err)
	}
	// A committed operation still returns its original safe result after expiry.
	_, err = s.IssueGrant(t.Context(), c, b)
	must(t, err)
}

func TestAccessSnapshotAtomicRulesAndCanonicalRetry(t *testing.T) {
	config := securityConfig(t)
	s := fixture(t, config)
	if _, err := s.AuthorizeAccess(t.Context(), "sender", "reports", "POST", "/api/v1/items", false); !errors.Is(err, ErrDenied) {
		t.Fatal("default allow")
	}
	c := change(t, 1)
	rules := accessRules()
	revision, err := s.ReplaceAccess(t.Context(), c, rules)
	must(t, err)
	if revision != 2 {
		t.Fatal("wrong policy revision")
	}
	rules.Policies[0].Paths = []string{"/api/v1", "/api/v2"}
	rules.Policies[0].Methods = []string{"GET", "POST"}
	repeated, err := s.ReplaceAccess(t.Context(), c, rules)
	must(t, err)
	if repeated != 2 {
		t.Fatal("canonical retry changed revision")
	}
	for _, tc := range []struct {
		caller, method, uri string
		user, allow         bool
	}{
		{"sender", "POST", "/api/v1/items", false, true}, {"sender", "POST", "/api/v1/internal/items", false, true},
		{"sender", "POST", "/api/v10/items", false, false}, {"sender", "DELETE", "/api/v1/items", false, false},
		{"sender", "POST", "/api/v1/items", true, false}, {"other", "POST", "/api/v1/items", false, false},
		{"sender", "POST", "/api/v1/%2fitems", false, false},
	} {
		_, err := s.AuthorizeAccess(t.Context(), tc.caller, "reports", tc.method, tc.uri, tc.user)
		if tc.allow {
			must(t, err)
		} else if !errors.Is(err, ErrDenied) {
			t.Fatal("unexpected authorization", tc, err)
		}
	}
	// Internal-only allowlist restricts even an otherwise matching allow rule.
	rules.Policies = append(rules.Policies, AccessPolicy{Caller: "other", Target: "reports", Paths: []string{"/api/v1"}, Methods: []string{"POST"}, AllowBackground: true})
	_, err = s.ReplaceAccess(t.Context(), change(t, 2), rules)
	must(t, err)
	if _, err := s.AuthorizeAccess(t.Context(), "other", "reports", "POST", "/api/v1/internal", false); !errors.Is(err, ErrDenied) {
		t.Fatal("internal-only bypass")
	}
	_, err = s.AuthorizeAccess(t.Context(), "other", "reports", "POST", "/api/v1/public", false)
	must(t, err)
	snapshot, _, err := s.Access(t.Context())
	must(t, err)
	snapshot.Policies[0].Paths[0] = "/changed"
	_, err = s.AuthorizeAccess(t.Context(), "sender", "reports", "POST", "/api/v1/public", false)
	must(t, err)
	must(t, s.Close())
	reopened, err := Open(t.Context(), config)
	must(t, err)
	defer reopened.Close()
	_, err = reopened.AuthorizeAccess(t.Context(), "sender", "reports", "POST", "/api/v1/public", false)
	must(t, err)
	_, err = reopened.ReplaceAccess(t.Context(), change(t, 3), AccessSnapshot{})
	must(t, err)
	if _, err := reopened.AuthorizeAccess(t.Context(), "sender", "reports", "POST", "/api/v1/public", false); !errors.Is(err, ErrDenied) {
		t.Fatal("deleted policy survived")
	}
}

func TestSecurityMutationsRollbackAndSharedRevision(t *testing.T) {
	for _, operation := range []string{"grant", "access"} {
		t.Run(operation, func(t *testing.T) {
			config := securityConfig(t)
			config.MaxOutboxBytes = 1
			s := fixture(t, config)
			if operation == "grant" {
				issued, err := s.IssueGrant(t.Context(), change(t, 1), binding())
				if !errors.Is(err, ErrOutboxFull) || issued.DeploymentGrant != "" {
					t.Fatal("failed mutation returned secret", err)
				}
			} else {
				_, err := s.ReplaceAccess(t.Context(), change(t, 1), accessRules())
				if !errors.Is(err, ErrOutboxFull) {
					t.Fatal(err)
				}
			}
			assertRevision(t, s, 1)
			for _, table := range []string{"deployment_grants", "security_results", "control_operations", "control_outbox"} {
				var count int
				must(t, s.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count))
				if count != 0 {
					t.Fatal("partial state retained", table)
				}
			}
			snapshot, _, err := s.Access(t.Context())
			must(t, err)
			if len(snapshot.Policies) != 0 {
				t.Fatal("failed policy published")
			}
		})
	}
	s := fixture(t, securityConfig(t))
	c := change(t, 1)
	issued, err := s.IssueGrant(t.Context(), c, binding())
	must(t, err)
	if _, err := s.ReplaceAccess(t.Context(), c, accessRules()); !errors.Is(err, ErrConflict) {
		t.Fatal("operation ID reused across endpoints", err)
	}
	if _, err := s.Revoke(t.Context(), Command{OperationID: c.OperationID, Actor: c.Actor, ExpectedRevision: 1, Reason: c.Reason, Target: Target{Kind: "grant_id", ServiceID: "reports", Value: issued.Record.GrantID}}); !errors.Is(err, ErrConflict) {
		t.Fatal("revoke reused grant operation", err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	grantChange, policyChange := change(t, 2), change(t, 2)
	group.Go(func() { _, err := s.IssueGrant(t.Context(), grantChange, binding()); results <- err })
	group.Go(func() { _, err := s.ReplaceAccess(t.Context(), policyChange, accessRules()); results <- err })
	group.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("grant/policy revisions diverged")
	}
	assertRevision(t, s, 3)
}

func TestSecurityValidationAndImmutableConfig(t *testing.T) {
	config := securityConfig(t)
	s := fixture(t, config)
	config.Services["reports"][0] = "/unrelated"
	_, err := s.IssueGrant(t.Context(), change(t, 1), binding())
	must(t, err)
	for _, modify := range []func(*GrantBinding){
		func(b *GrantBinding) { b.ExpiresAt = time.Now().Add(2 * time.Hour) }, func(b *GrantBinding) { b.ExpiresAt = time.Now().Add(-time.Minute) }, func(b *GrantBinding) { b.Paths = []string{"/api/v1", "/api/v1"} },
		func(b *GrantBinding) { b.Paths = []string{"/foreign"} }, func(b *GrantBinding) { b.Paths = []string{"/"} }, func(b *GrantBinding) { b.Mounts = map[string]string{"api": "/foreign"} },
		func(b *GrantBinding) { b.PathMode = "preserve" }, func(b *GrantBinding) { b.SPKI = "not-hex" }, func(b *GrantBinding) { b.ArtifactDigest = "unverified" },
	} {
		b := binding()
		modify(&b)
		if _, err := s.IssueGrant(t.Context(), change(t, 2), b); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid grant accepted", err)
		}
	}
	for _, modify := range []func(*AccessSnapshot){
		func(a *AccessSnapshot) { a.Policies[0].Caller = "*" }, func(a *AccessSnapshot) { a.Policies[0].Target = "unknown" }, func(a *AccessSnapshot) { a.Policies[0].Paths = []string{"/"} },
		func(a *AccessSnapshot) { a.Policies[0].Methods = []string{"*"} }, func(a *AccessSnapshot) { a.Policies[0].AllowBackground = false }, func(a *AccessSnapshot) { a.Policies = append(a.Policies, a.Policies[0]) },
		func(a *AccessSnapshot) { a.InternalOnly[0].Callers = []string{"unknown"} },
	} {
		a := accessRules()
		modify(&a)
		if _, err := s.ReplaceAccess(t.Context(), change(t, 2), a); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid policy accepted", err)
		}
	}
}

func TestExpiredCommittedGrantRetryStillReturnsMetadata(t *testing.T) {
	s := fixture(t, securityConfig(t))
	b := binding()
	b.ExpiresAt = time.Now().Add(time.Second)
	c := change(t, 1)
	original, err := s.IssueGrant(t.Context(), c, b)
	must(t, err)
	timer := time.NewTimer(time.Until(b.ExpiresAt) + time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	repeated, err := s.IssueGrant(t.Context(), c, b)
	must(t, err)
	if repeated.DeploymentGrant != "" || repeated.Record.GrantID != original.Record.GrantID {
		t.Fatal("expired retry returned different grant or secret")
	}
	if _, err := s.GrantForPeer(t.Context(), original.Record.GrantID, peer()); !errors.Is(err, ErrDenied) {
		t.Fatal("expired retry reactivated grant")
	}
}

func TestSecurityAuditInsertFailureRollsBackEveryWrite(t *testing.T) {
	for _, kind := range []string{"grant", "access"} {
		t.Run(kind, func(t *testing.T) {
			s := fixture(t, securityConfig(t))
			_, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER reject_security_audit BEFORE INSERT ON control_outbox BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`)
			must(t, err)
			if kind == "grant" {
				issued, err := s.IssueGrant(t.Context(), change(t, 1), binding())
				if !errors.Is(err, ErrUnavailable) || issued.DeploymentGrant != "" {
					t.Fatal("failed commit leaked credential", err)
				}
			} else {
				_, err := s.ReplaceAccess(t.Context(), change(t, 1), accessRules())
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal(err)
				}
			}
			assertRevision(t, s, 1)
			for _, table := range []string{"deployment_grants", "security_results", "control_operations", "control_outbox"} {
				var count int
				must(t, s.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count))
				if count != 0 {
					t.Fatal("failed outbox left committed state", table)
				}
			}
			snapshot, _, err := s.Access(t.Context())
			must(t, err)
			if len(snapshot.Policies) != 0 {
				t.Fatal("failed outbox published access rules")
			}
		})
	}
}
