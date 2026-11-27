package servicecall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/solodyagin/outgate-sdk/delegation"
	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
)

type stateFixture struct {
	f            *fixture
	store        *controlstate.Store
	grant        controlstate.GrantRecord
	config       Config
	state        StateConfig
	keysMu       sync.RWMutex
	keys         map[string]AcceptedKey
	keyCalls     atomic.Int32
	resolveCalls atomic.Int32
	inspect      func(*http.Request)
}

func stateChange(t *testing.T, s *controlstate.Store) controlstate.Change {
	t.Helper()
	revision, err := s.Revision(t.Context())
	must(t, err)
	id, err := uuid.NewV7()
	must(t, err)
	return controlstate.Change{OperationID: id.String(), Actor: "security-admin", ExpectedRevision: revision, Reason: "integration check"}
}
func stateRules() controlstate.AccessSnapshot {
	return controlstate.AccessSnapshot{Policies: []controlstate.AccessPolicy{{Caller: callerID, Target: targetID, Paths: []string{"/api"}, Methods: []string{"POST"}, AllowBackground: true}}}
}
func newStateFixture(t *testing.T, limits CallerLimit) *stateFixture {
	t.Helper()
	s := &stateFixture{f: testFixture(t)}
	c := controlstate.Config{Path: filepath.Join(t.TempDir(), "control.db"), Epoch: [32]byte{1}, Services: map[string][]string{callerID: {"/sender"}, targetID: {"/api"}}}
	must(t, controlstate.Initialize(t.Context(), c))
	var err error
	s.store, err = controlstate.Open(t.Context(), c)
	must(t, err)
	t.Cleanup(func() { _ = s.store.Close() })
	spki := sha256.Sum256(s.f.clientTLS.Certificates[0].Leaf.RawSubjectPublicKeyInfo)
	issued, err := s.store.IssueGrant(t.Context(), stateChange(t, s.store), controlstate.GrantBinding{ServiceID: callerID, InstanceID: "sender-1", Version: "v1", Paths: []string{"/sender"}, Mounts: map[string]string{}, PathMode: "preserve", SPKI: hex.EncodeToString(spki[:]), ArtifactDigest: "sha256:" + strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour / 2)})
	must(t, err)
	s.grant = issued.Record
	_, err = s.store.ReplaceAccess(t.Context(), stateChange(t, s.store), stateRules())
	must(t, err)
	s.keys = map[string]AcceptedKey{httpsig.Call: {Key: s.f.call, NotAfter: time.Now().Add(time.Hour)}, httpsig.Gateway: {Key: s.f.recipient, NotAfter: time.Now().Add(time.Hour)}}
	s.state = StateConfig{Store: s.store, Callers: map[string]CallerLimit{callerID: limits}, Keys: func(_ context.Context, leg, service, id string) (AcceptedKey, error) {
		s.keyCalls.Add(1)
		if leg == httpsig.Call && service != callerID || leg == httpsig.Gateway && service != targetID {
			return AcceptedKey{}, controlstate.ErrDenied
		}
		s.keysMu.RLock()
		defer s.keysMu.RUnlock()
		accepted, ok := s.keys[leg]
		if !ok || accepted.Key.ID != id {
			return AcceptedKey{}, controlstate.ErrDenied
		}
		return accepted, nil
	}}
	config := s.f.config
	config.Authenticate, config.Authorize = nil, nil
	config.Resolve = func(_ context.Context, route registry.Decision) (Recipient, error) {
		s.resolveCalls.Add(1)
		return Recipient{Key: s.f.recipient, Transport: transport{handle: s.f.selected, send: func(req *http.Request) (*http.Response, error) {
			s.f.calls.Add(1)
			if s.inspect != nil {
				s.inspect(req)
			}
			var headers []v1.Header
			for name, values := range req.Header {
				for _, value := range values {
					headers = append(headers, v1.Header{strings.ToLower(name), value})
				}
			}
			verifier, err := delivery.New(delivery.Config{Leg: httpsig.Gateway})
			if err != nil {
				return nil, err
			}
			_, err = verifier.Verify(httpsig.Request{Method: req.Method, Scheme: req.URL.Scheme, Authority: req.Host, RawURI: req.URL.RequestURI(), Headers: headers}, s.f.recipient, delivery.Binding{Caller: callerID, Target: targetID, GrantID: s.grant.GrantID, Instance: "target-1", Version: "v1", Prefix: "/api"}, time.Now())
			if err != nil {
				t.Error("state-backed recipient signature invalid", err)
				return nil, err
			}
			_, err = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("state-backed"))}, nil
		}}}, nil
	}
	s.config, err = BindStateAdmission(config, s.state)
	must(t, err)
	return s
}
func (s *stateFixture) request(t *testing.T, address, uri string) *http.Request {
	t.Helper()
	req := signedRequest(t, address, uri, callerID, 0, s.f.call)
	req.Header.Set("X-Outgate-Deployment-Grant-Id", s.grant.GrantID)
	var headers []v1.Header
	for name, values := range req.Header {
		if strings.EqualFold(name, "Signature") || strings.EqualFold(name, "Signature-Input") {
			continue
		}
		for _, value := range values {
			headers = append(headers, v1.Header{strings.ToLower(name), value})
		}
	}
	profile, err := httpsig.New(httpsig.Config{Leg: httpsig.Call})
	must(t, err)
	signature, err := profile.Sign(httpsig.Request{Method: req.Method, Scheme: "https", Authority: req.Host, RawURI: req.URL.RequestURI(), Headers: headers}, s.f.call.ID, s.f.call.Secret, time.Now())
	must(t, err)
	req.Header.Set("Signature", signature.Signature)
	req.Header.Set("Signature-Input", signature.SignatureInput)
	return req
}
func (s *stateFixture) server(t *testing.T) (string, *http.Client) {
	t.Helper()
	configured, err := NewServer(s.config)
	must(t, err)
	return runServer(t, configured, s.f.clientTLS)
}

func TestStateAdmissionMTLSPolicyGrantAndSingleDecode(t *testing.T) {
	s := newStateFixture(t, CallerLimit{PerSecond: 100, Burst: 100})
	address, client := s.server(t)
	for _, uri := range []string{publicURI, "/api/%252f?opaque=%252f"} {
		response := send(t, client, s.request(t, address, uri), 200)
		body, err := io.ReadAll(response.Body)
		must(t, err)
		if string(body) != "state-backed" {
			t.Fatal("invalid recipient response")
		}
	}
	if s.f.calls.Load() != 2 || s.resolveCalls.Load() != 2 {
		t.Fatal("unexpected dispatch count")
	}
	_, err := s.store.ReplaceAccess(t.Context(), stateChange(t, s.store), controlstate.AccessSnapshot{})
	must(t, err)
	before := s.f.replay.count()
	send(t, client, s.request(t, address, publicURI), 403)
	if s.f.replay.count() != before || s.f.calls.Load() != 2 {
		t.Fatal("denied policy spent nonce or dispatched")
	}
}

func TestStateAdmissionRechecksAfterReplayCommitWithoutReselect(t *testing.T) {
	for _, kind := range []string{"caller-service", "caller-grant", "caller-spki", "caller-certificate", "caller-key", "recipient-key", "recipient-service", "policy", "closed-store", "changed-key", "shortened-key", "recipient-shortened"} {
		t.Run(kind, func(t *testing.T) {
			s := newStateFixture(t, CallerLimit{PerSecond: 100, Burst: 100})
			change := stateChange(t, s.store)
			hookErr := make(chan error, 1)
			status := 401
			if strings.HasPrefix(kind, "recipient-") || kind == "closed-store" || kind == "shortened-key" {
				status = 503
			}
			if kind == "policy" {
				status = 403
			}
			s.f.replay.afterCommit = func() {
				var err error
				switch kind {
				case "policy":
					_, err = s.store.ReplaceAccess(context.Background(), change, controlstate.AccessSnapshot{})
				case "closed-store":
					err = s.store.Close()
				case "changed-key":
					s.keysMu.Lock()
					updated := s.keys[httpsig.Call]
					updated.Key.Secret = bytes.Repeat([]byte{99}, 32)
					s.keys[httpsig.Call] = updated
					s.keysMu.Unlock()
				case "shortened-key", "recipient-shortened":
					leg := httpsig.Call
					if kind == "recipient-shortened" {
						leg = httpsig.Gateway
					}
					s.keysMu.Lock()
					updated := s.keys[leg]
					updated.NotAfter = time.Now().Add(time.Second)
					s.keys[leg] = updated
					s.keysMu.Unlock()
				default:
					target := controlstate.Target{ServiceID: callerID}
					switch kind {
					case "caller-service":
						target.Kind = "service"
					case "caller-grant":
						target.Kind = "grant_id"
						target.Value = s.grant.GrantID
					case "caller-spki":
						target.Kind = "spki_sha256"
						target.Value = s.grant.SPKI
					case "caller-certificate":
						target.Kind = "certificate_serial"
						target.Value = s.f.clientTLS.Certificates[0].Leaf.SerialNumber.Text(16)
					case "caller-key":
						target.Kind = "hmac_key_id"
						target.Value = s.f.call.ID
					case "recipient-key":
						target.Kind = "hmac_key_id"
						target.ServiceID = targetID
						target.Value = s.f.recipient.ID
					case "recipient-service":
						target.Kind = "service"
						target.ServiceID = targetID
					}
					_, err = s.store.Revoke(context.Background(), controlstate.Command{OperationID: change.OperationID, Actor: change.Actor, ExpectedRevision: change.ExpectedRevision, Reason: change.Reason, Target: target})
				}
				hookErr <- err
			}
			address, client := s.server(t)
			send(t, client, s.request(t, address, publicURI), status)
			must(t, <-hookErr)
			if s.f.calls.Load() != 0 || s.resolveCalls.Load() != 1 || s.f.replay.count() != 1 {
				t.Fatal("post-commit denial dispatched/reselected or lost nonce")
			}
		})
	}
}

func TestStateAdmissionRateLimitPrecedesStateAndKeys(t *testing.T) {
	s := newStateFixture(t, CallerLimit{PerSecond: 1, Burst: 1})
	// The constructor owns its fixed-size limit snapshot.
	s.state.Callers[callerID] = CallerLimit{PerSecond: 1000000, Burst: 1000000}
	address, client := s.server(t)
	send(t, client, s.request(t, address, publicURI), 200)
	calls := s.keyCalls.Load()
	must(t, s.store.Close())
	send(t, client, s.request(t, address, publicURI), 429)
	if s.keyCalls.Load() != calls || s.f.replay.count() != 1 {
		t.Fatal("rate-limited caller reached key source or replay")
	}
}

func TestCallerBucketConcurrencyRefillAndUnknownIdentity(t *testing.T) {
	now := time.Now()
	a := &stateAdmission{callers: map[string]*callerBucket{callerID: {limit: CallerLimit{PerSecond: 2, Burst: 7}, tokens: 7, last: now}}}
	var group sync.WaitGroup
	var allowed atomic.Int32
	for range 50 {
		group.Go(func() {
			if a.take(callerID, now) == nil {
				allowed.Add(1)
			}
		})
	}
	group.Wait()
	if allowed.Load() != 7 {
		t.Fatal("burst quota raced", allowed.Load())
	}
	if err := a.take(callerID, now.Add(500*time.Millisecond)); err != nil {
		t.Fatal("refill failed", err)
	}
	if !errors.Is(a.take(callerID, now.Add(500*time.Millisecond)), ErrRateLimited) {
		t.Fatal("refill over-admitted")
	}
	if !errors.Is(a.take(callerID, now.Add(-time.Hour)), ErrRateLimited) {
		t.Fatal("backward clock refilled quota")
	}
	if !errors.Is(a.take("unknown", now), delivery.ErrDelivery) || len(a.callers) != 1 {
		t.Fatal("unknown identity allocated bucket")
	}
}

func TestStateAdmissionRecipientKeyDeadlineAndSourceFailure(t *testing.T) {
	for _, mode := range []string{"deadline", "caller-deadline", "grant-deadline", "wrong-leg-key", "expired-caller", "source-error"} {
		t.Run(mode, func(t *testing.T) {
			s := newStateFixture(t, CallerLimit{PerSecond: 100, Burst: 100})
			until := time.Now().Add(2 * time.Second)
			status := 200
			switch mode {
			case "deadline":
				s.keys[httpsig.Gateway] = AcceptedKey{Key: s.f.recipient, NotAfter: until}
				s.inspect = func(req *http.Request) {
					deadline, ok := req.Context().Deadline()
					if !ok || !deadline.Equal(until) {
						t.Error("recipient expiry did not cap exchange", deadline, until)
					}
				}
			case "caller-deadline", "grant-deadline":
				if mode == "caller-deadline" {
					s.keys[httpsig.Call] = AcceptedKey{Key: s.f.call, NotAfter: until}
				} else {
					b := s.grant.GrantBinding
					b.ExpiresAt = until
					issued, err := s.store.IssueGrant(t.Context(), stateChange(t, s.store), b)
					must(t, err)
					s.grant = issued.Record
				}
				s.inspect = func(req *http.Request) {
					deadline, ok := req.Context().Deadline()
					if !ok || !deadline.Equal(until) {
						t.Error("caller key/grant expiry did not cap exchange", deadline, until)
					}
				}
			case "wrong-leg-key":
				s.keys[httpsig.Gateway] = AcceptedKey{Key: s.f.call, NotAfter: until}
				status = 503
			case "expired-caller":
				s.keys[httpsig.Call] = AcceptedKey{Key: s.f.call, NotAfter: time.Now().Add(-time.Second)}
				status = 401
			case "source-error":
				s.config.Authenticate = nil
				s.config.Authorize = nil
				s.config.Revalidate = nil
				s.state.Keys = func(context.Context, string, string, string) (AcceptedKey, error) {
					return AcceptedKey{}, controlstate.ErrUnavailable
				}
				var err error
				s.config, err = BindStateAdmission(s.config, s.state)
				must(t, err)
				status = 503
			}
			address, client := s.server(t)
			send(t, client, s.request(t, address, publicURI), status)
			if status != 200 && (s.f.calls.Load() != 0 || s.f.replay.count() != 0) {
				t.Fatal("invalid key/state reached replay or transport")
			}
		})
	}
}

func TestStateAdmissionUserRevocationBoundary(t *testing.T) {
	s := newStateFixture(t, CallerLimit{PerSecond: 100, Burst: 100})
	rules := stateRules()
	rules.Policies[0].AllowUserContext = true
	_, err := s.store.ReplaceAccess(t.Context(), stateChange(t, s.store), rules)
	must(t, err)
	cert := s.f.clientTLS.Certificates[0].Leaf
	call := Call{Peer: Peer{ServiceID: callerID, InstanceID: "sender-1", Certificate: cert, SPKI: sha256.Sum256(cert.RawSubjectPublicKeyInfo)}, GrantID: s.grant.GrantID, Target: targetID, Method: "POST", Path: "/api/items", RawURI: publicURI, KeyID: s.f.call.ID, HasUser: true, User: delegation.Identity{Issuer: "https://issuer.test", Actor: callerID, Target: targetID, Subject: "user-1", SessionID: "session-1", TokenID: "token-1", ExpiresAt: time.Now().Add(time.Hour)}}
	admission := &stateAdmission{config: s.state}
	if _, err := admission.authorize(t.Context(), call); !errors.Is(err, ErrForbidden) {
		t.Fatal("user call accepted without revocation source", err)
	}
	until := time.Now().Add(time.Second)
	admission.config.CheckUser = func(_ context.Context, identity delegation.Identity) (time.Time, error) {
		if identity != call.User {
			t.Error("verified identity changed")
		}
		return until, nil
	}
	lease, err := admission.authorize(t.Context(), call)
	must(t, err)
	if !lease.Equal(until) {
		t.Fatal("user revocation lease did not cap exchange")
	}
	admission.config.CheckUser = func(context.Context, delegation.Identity) (time.Time, error) {
		return time.Time{}, controlstate.ErrDenied
	}
	if _, err := admission.authorize(t.Context(), call); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked user admitted", err)
	}
	admission.config.CheckUser = func(context.Context, delegation.Identity) (time.Time, error) { return time.Time{}, nil }
	if _, err := admission.authorize(t.Context(), call); !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal("missing user lease admitted", err)
	}
}

func TestStateAdmissionRequiresCompleteUnmixedConfiguration(t *testing.T) {
	s := newStateFixture(t, CallerLimit{PerSecond: 100, Burst: 100})
	base := s.config
	base.Authenticate = nil
	base.Authorize = nil
	base.Revalidate = nil
	for _, modify := range []func(*StateConfig){
		func(c *StateConfig) { c.Store = nil }, func(c *StateConfig) { c.Keys = nil }, func(c *StateConfig) { c.Callers = nil },
		func(c *StateConfig) { c.Callers = map[string]CallerLimit{callerID: {PerSecond: 0, Burst: 1}} },
		func(c *StateConfig) { c.Callers = map[string]CallerLimit{callerID: {PerSecond: 1, Burst: 0}} },
		func(c *StateConfig) { c.Callers = map[string]CallerLimit{"*": {PerSecond: 1, Burst: 1}} },
	} {
		config := s.state
		modify(&config)
		if _, err := BindStateAdmission(base, config); !errors.Is(err, ErrConfig) {
			t.Fatal("incomplete state admission accepted", err)
		}
	}
	if _, err := BindStateAdmission(s.config, s.state); !errors.Is(err, ErrConfig) {
		t.Fatal("mixed callback admission accepted", err)
	}
	base.Resolve = nil
	if _, err := BindStateAdmission(base, s.state); !errors.Is(err, ErrConfig) {
		t.Fatal("missing transport resolver accepted", err)
	}
}

func TestStateAdmissionCopiesAcceptedKeyMaterial(t *testing.T) {
	s := newStateFixture(t, CallerLimit{PerSecond: 100, Burst: 100})
	cert := s.f.clientTLS.Certificates[0].Leaf
	peer := Peer{ServiceID: callerID, InstanceID: "sender-1", Certificate: cert, SPKI: sha256.Sum256(cert.RawSubjectPublicKeyInfo)}
	first, err := s.config.Authenticate(t.Context(), peer, s.grant.GrantID, s.f.call.ID)
	must(t, err)
	first.Secret[0] ^= 255
	second, err := s.config.Authenticate(t.Context(), peer, s.grant.GrantID, s.f.call.ID)
	must(t, err)
	if !bytes.Equal(second.Secret, s.f.call.Secret) {
		t.Fatal("key mutation escaped lookup snapshot")
	}
}
