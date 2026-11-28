package gateway

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
	"github.com/solodyagin/outgate/internal/servicecall"
)

type recipientTransport struct{ handle *registry.Session }

func (s recipientTransport) Handle() *registry.Session { return s.handle }
func (s recipientTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected test dispatch")
}

func recipientRoute(t *testing.T, config Config) registry.Decision {
	t.Helper()
	routes, err := registry.New(config.Tunnel.Registry)
	check(t, err)
	// Isolate resolver composition: real durable admission checks use SQLite below,
	// while this transport handle is explicitly synthetic and cannot dispatch.
	registration, err := routes.RegisterAuthorized(v1.Register{Type: "register", ProtocolVersion: 1, ServiceID: "api", InstanceID: "one", Version: "1.0.0", Paths: []string{"/api"}, PathMode: "preserve", MaxConcurrentRequests: 100, Capabilities: v1.BaselineCapabilities(), RequiredCapabilities: v1.BaselineCapabilities()}, registry.QUIC)
	check(t, err)
	return registry.Decision{ServiceID: "api", Session: registration.Session}
}

func TestRecipientResolverSuppliesActiveKeyToDurableAdmission(t *testing.T) {
	config := sqliteConfig(t)
	route := recipientRoute(t, config)
	store, err := controlstate.Open(t.Context(), config.Tunnel.Control)
	check(t, err)
	defer store.Close()
	secret := bytes.Repeat([]byte{1}, 32)
	deadline := time.Now().Add(time.Minute)
	calls, resolutions := 0, 0
	config.State.Store = store
	config.State.Keys = func(_ context.Context, leg, service, id string) (servicecall.AcceptedKey, error) {
		calls++
		if leg != httpsig.Gateway || service != "api" || id != "gateway-api-1" {
			t.Fatal("key lookup crossed identity", leg, service, id)
		}
		return servicecall.AcceptedKey{Key: delivery.Key{ID: id, Secret: secret}, NotAfter: deadline}, nil
	}
	active, err := activeRecipientKeys(config)
	check(t, err)
	resolve := func(context.Context, registry.Decision) (servicecall.Recipient, error) {
		resolutions++
		return servicecall.Recipient{Transport: recipientTransport{route.Session}}, nil
	}
	bound, err := bindRecipientAdmission(servicecall.Config{}, config.State, resolve, active)
	check(t, err)
	recipient, err := bound.Resolve(t.Context(), route)
	check(t, err)
	if recipient.Key.ID != "gateway-api-1" || !bytes.Equal(recipient.Key.Secret, secret) || !recipient.ValidUntil.Equal(deadline) || recipient.Transport.Handle() != route.Session || calls != 2 || resolutions != 1 {
		t.Fatal("missing active key or durable recheck", recipient.Key.ID, calls, resolutions)
	}
	secret[0] = 99
	if recipient.Key.Secret[0] != 1 {
		t.Fatal("source mutated accepted snapshot")
	}
}

func TestRecipientResolverDurableRecheckRejectsRotationAndRevocation(t *testing.T) {
	for _, reason := range []string{"rotation", "revocation"} {
		t.Run(reason, func(t *testing.T) {
			config := sqliteConfig(t)
			route := recipientRoute(t, config)
			store, err := controlstate.Open(t.Context(), config.Tunnel.Control)
			check(t, err)
			defer store.Close()
			calls, resolutions := 0, 0
			config.State.Store = store
			config.State.Keys = func(_ context.Context, leg, service, id string) (servicecall.AcceptedKey, error) {
				calls++
				if leg != httpsig.Gateway || service != route.ServiceID || id != "gateway-api-1" {
					t.Fatal("changed selected key")
				}
				if reason == "revocation" && calls == 1 {
					revision, err := store.Revision(t.Context())
					check(t, err)
					operation, err := uuid.NewV7()
					check(t, err)
					_, err = store.Revoke(t.Context(), controlstate.Command{OperationID: operation.String(), Actor: "security-admin", ExpectedRevision: revision, Reason: "resolver recheck", Target: controlstate.Target{Kind: "hmac_key_id", ServiceID: "api", Value: id}})
					check(t, err)
				}
				value := byte(1)
				if calls > 1 {
					value = 2
				}
				return servicecall.AcceptedKey{Key: delivery.Key{ID: id, Secret: bytes.Repeat([]byte{value}, 32)}, NotAfter: time.Now().Add(time.Minute)}, nil
			}
			active, err := activeRecipientKeys(config)
			check(t, err)
			resolve := func(context.Context, registry.Decision) (servicecall.Recipient, error) {
				resolutions++
				return servicecall.Recipient{Transport: recipientTransport{route.Session}}, nil
			}
			bound, err := bindRecipientAdmission(servicecall.Config{}, config.State, resolve, active)
			check(t, err)
			if _, err = bound.Resolve(t.Context(), route); err == nil {
				t.Fatal("accepted changed/revoked key")
			}
			expected := 2
			if reason == "revocation" {
				expected = 1
			}
			if resolutions != 1 || calls != expected {
				t.Fatal("reselected or retried", resolutions, calls)
			}
		})
	}
}

func TestRecipientResolverRejectsInvalidSourceWithoutFallback(t *testing.T) {
	config := sqliteConfig(t)
	route := recipientRoute(t, config)
	for _, reason := range []string{"wrong-id", "short", "oversized", "expired", "error", "canceled"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			resolver := recipientResolver(func(context.Context, registry.Decision) (servicecall.Recipient, error) {
				return servicecall.Recipient{Transport: recipientTransport{route.Session}}, nil
			}, map[string]string{"api": "active"}, func(context.Context, string, string, string) (servicecall.AcceptedKey, error) {
				calls++
				accepted := servicecall.AcceptedKey{Key: delivery.Key{ID: "active", Secret: bytes.Repeat([]byte{1}, 32)}, NotAfter: time.Now().Add(time.Minute)}
				switch reason {
				case "wrong-id":
					accepted.Key.ID = "other"
				case "short":
					accepted.Key.Secret = accepted.Key.Secret[:31]
				case "oversized":
					accepted.Key.Secret = make([]byte, 4097)
				case "expired":
					accepted.NotAfter = time.Now().Add(-time.Second)
				case "error":
					return servicecall.AcceptedKey{}, errors.New("unavailable")
				case "canceled":
					cancel()
				}
				return accepted, nil
			})
			if _, err := resolver(ctx, route); err == nil || calls != 1 {
				t.Fatal("invalid source accepted or retried", err, calls)
			}
		})
	}
}

func TestRecipientResolverRejectsUnknownTargetBeforeKeyLookup(t *testing.T) {
	config := sqliteConfig(t)
	route := recipientRoute(t, config)
	calls := 0
	resolver := recipientResolver(func(context.Context, registry.Decision) (servicecall.Recipient, error) {
		return servicecall.Recipient{Transport: recipientTransport{route.Session}}, nil
	}, map[string]string{"other": "active"}, func(context.Context, string, string, string) (servicecall.AcceptedKey, error) {
		calls++
		return servicecall.AcceptedKey{}, nil
	})
	if _, err := resolver(t.Context(), route); err == nil || calls != 0 {
		t.Fatal("unconfigured target reached key source", err, calls)
	}
}

func TestActiveRecipientKeyIDsAreValidatedAndDetached(t *testing.T) {
	config := sqliteConfig(t)
	active, err := activeRecipientKeys(config)
	check(t, err)
	config.RecipientKeyIDs["api"] = "changed"
	if active["api"] != "gateway-api-1" {
		t.Fatal("retained mutable configuration")
	}
	for _, mapping := range []map[string]string{nil, {}, {"unknown": "key"}, {"api": ""}, {"api": "bad key"}, {"api": strings.Repeat("x", 129)}} {
		config.RecipientKeyIDs = mapping
		if _, err := activeRecipientKeys(config); !errors.Is(err, servicecall.ErrConfig) {
			t.Fatal("accepted invalid active IDs", err)
		}
	}
}
