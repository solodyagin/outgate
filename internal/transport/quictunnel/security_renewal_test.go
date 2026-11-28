package quictunnel

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
)

func TestDurableRenewalSurvivesWarmupAndBecomesReady(t *testing.T) {
	f := durableAdmissionFixture(t)
	barrier := time.Now().Add(1200 * time.Millisecond)
	var checks atomic.Int32
	f.config.Renewal = SecurityRenewal{Interval: 20 * time.Millisecond, Timeout: time.Second}
	f.config.Security = func(context.Context) (AdmissionSecurity, error) {
		checks.Add(1)
		return AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second), ReadyNotBefore: barrier}, nil
	}
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	bound, carrier, ack, openErr, acceptErr := f.open(t, a)
	must(t, openErr)
	must(t, acceptErr)
	must(t, bound.RenewSecurity(true, time.Now().Add(time.Second)))
	must(t, bound.EnableDispatch())
	must(t, carrier.Send(t.Context(), v1.InstanceStatus{Type: "instance_status", Sequence: 1, Ready: true, Code: "ready", ObservedAt: 0}))
	eventually(t, func() bool { return checks.Load() >= 5 })
	if bound.Snapshot().Phase == sessionstate.Ready && time.Now().Unix() < ack.ReadyNotBefore {
		t.Fatal("renewal bypassed replay barrier")
	}
	eventually(t, func() bool { return bound.Snapshot().Phase == sessionstate.Ready })
	if !bound.Snapshot().TransportActive || checks.Load() < 5 {
		t.Fatal("renewal lost registered-but-unready session")
	}
	must(t, f.config.Owner.Routes().CanDispatch(bound.Handle()))
	for _, path := range ack.Paths {
		if path.State != "pending" {
			t.Fatal("renewal activated ownership")
		}
	}
}

func TestDurableRenewalRejectsRevocationHealthTimeoutAndSaturation(t *testing.T) {
	for _, fault := range []string{"revoked", "health", "timeout", "saturation", "publication", "new_barrier"} {
		t.Run(fault, func(t *testing.T) {
			f := durableAdmissionFixture(t)
			var failed atomic.Bool
			f.config.Renewal = SecurityRenewal{Interval: 20 * time.Millisecond, Timeout: 50 * time.Millisecond}
			f.config.Security = func(ctx context.Context) (AdmissionSecurity, error) {
				if failed.Load() && fault != "new_barrier" {
					if fault == "timeout" {
						<-ctx.Done()
					} else {
						return AdmissionSecurity{}, controlstate.ErrUnavailable
					}
				}
				state := AdmissionSecurity{ValidUntil: time.Now().Add(500 * time.Millisecond)}
				if failed.Load() && fault == "new_barrier" {
					state.ReadyNotBefore = time.Now().Add(120 * time.Second)
				}
				return state, nil
			}
			a, err := NewDurableAdmission(f.config)
			must(t, err)
			bound, _, _, openErr, acceptErr := f.open(t, a)
			must(t, openErr)
			must(t, acceptErr)
			switch fault {
			case "revoked":
				id, _, _ := strings.Cut(f.credential, ".")
				revision, err := f.store.Revision(t.Context())
				must(t, err)
				operation, err := uuid.NewV7()
				must(t, err)
				_, err = f.store.Revoke(t.Context(), controlstate.Command{OperationID: operation.String(), Actor: "security-admin", ExpectedRevision: revision, Reason: "renewal acceptance revocation", Target: controlstate.Target{Kind: "grant_id", ServiceID: f.reg.ServiceID, Value: id}})
				must(t, err)
			case "health", "timeout", "new_barrier":
				failed.Store(true)
			case "saturation":
				for range cap(a.renewSlots) {
					a.renewSlots <- struct{}{}
				}
				defer func() {
					for range cap(a.renewSlots) {
						<-a.renewSlots
					}
				}()
			case "publication":
				reg := f.reg
				reg.InstanceID = "uncertain"
				_, err = f.config.Owner.Routes().CommitRegistrationAuthorized(reg, registry.QUIC, func([]byte, uint64) error { return controlstate.ErrUnavailable })
				if !errors.Is(err, controlstate.ErrUnavailable) {
					t.Fatal("expected publication failure", err)
				}
			}
			await(t, bound.Done())
			if !errors.Is(bound.Err(), sessionstate.ErrSecurity) {
				t.Fatal("renewal did not revoke", bound.Err())
			}
			if f.gateway.Context().Err() == nil {
				t.Fatal("renewal released before native close")
			}
			durable, err := f.store.LoadRegistry(t.Context(), f.registryConfig, 5)
			must(t, err)
			if durable.Commit.RegistryRevision != 1 {
				t.Fatal("revocation discarded ownership")
			}
			must(t, f.store.Close())
		})
	}
}

func TestBlockedRenewalExpiresIndependentlyAndRetainsOwnership(t *testing.T) {
	f := durableAdmissionFixture(t)
	f.config.Bound.TickInterval = time.Second
	f.config.Renewal = SecurityRenewal{Interval: 20 * time.Millisecond, Timeout: time.Second}
	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	var checks atomic.Int32
	f.config.Security = func(context.Context) (AdmissionSecurity, error) {
		if checks.Add(1) > 2 {
			entered <- struct{}{}
			<-unblock
		}
		return AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second)}, nil
	}
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	bound, _, _, openErr, acceptErr := f.open(t, a)
	must(t, openErr)
	must(t, acceptErr)
	await(t, entered)
	must(t, bound.RenewSecurity(true, time.Now().Add(200*time.Millisecond)))
	select {
	case <-f.gateway.Context().Done():
	case <-time.After(900 * time.Millisecond):
		t.Fatal("lease expiry waited for blocked checker/periodic tick")
	}
	if checks.Load() != 3 || len(a.renewSlots) != 1 {
		t.Fatal("blocked callbacks accumulated")
	}
	if _, err := f.store.AcquireRegistration(t.Context(), f.credential, f.peer, f.reg); !errors.Is(err, controlstate.ErrInstanceInUse) {
		t.Fatal("blocked callback released ownership", err)
	}
	if err := f.store.Close(); !errors.Is(err, controlstate.ErrInstanceInUse) {
		t.Fatal("closed store under callback", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := bound.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup ignored outstanding callback", err)
	}
	once.Do(func() { close(unblock) })
	await(t, bound.Done())
	if len(a.renewSlots) != 0 || !errors.Is(bound.Err(), sessionstate.ErrSecurity) {
		t.Fatal("late result revived transport or leaked slot", bound.Err())
	}
	must(t, f.store.Close())
}

func TestDurableRenewalCannotExtendGrantOrLegacyDeadline(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "grant", true: "legacy"}[legacy], func(t *testing.T) {
			ttl := time.Duration(2) * time.Second
			if legacy {
				ttl = 10 * time.Minute
			}
			f := durableAdmissionFixtureTTL(t, ttl)
			f.config.Renewal = SecurityRenewal{Interval: 20 * time.Millisecond, Timeout: 500 * time.Millisecond}
			a, err := NewDurableAdmission(f.config)
			must(t, err)
			bound, _, ack, openErr, acceptErr := f.open(t, a)
			must(t, openErr)
			must(t, acceptErr)
			if legacy {
				must(t, bound.SetSecurity(true, time.Now().Add(100*time.Millisecond)))
			}
			await(t, bound.Done())
			if !errors.Is(bound.Err(), sessionstate.ErrSecurity) {
				t.Fatal("renewal bypassed expiry", bound.Err())
			}
			if !legacy && time.Now().Unix() < *ack.CredentialExpiresAt {
				t.Fatal("unexpected early expiration")
			}
		})
	}
}

func TestRenewalExpiryInterruptsNativeIOWhileRegistryCommitHoldsLock(t *testing.T) {
	f := durableAdmissionFixture(t)
	f.config.Bound.TickInterval = time.Second
	f.config.Security = func(context.Context) (AdmissionSecurity, error) {
		return AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second)}, nil
	}
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	bound, _, _, openErr, acceptErr := f.open(t, a)
	must(t, openErr)
	must(t, acceptErr)
	must(t, bound.RenewSecurity(true, time.Now().Add(500*time.Millisecond)))
	entered := make(chan struct{})
	unblock := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	persisted := make(chan error, 1)
	reg := f.reg
	reg.InstanceID = "slow-publication"
	go func() {
		_, err := f.config.Owner.Routes().CommitRegistrationAuthorized(reg, registry.QUIC, func([]byte, uint64) error { close(entered); <-unblock; return controlstate.ErrUnavailable })
		persisted <- err
	}()
	await(t, entered)
	select {
	case <-f.gateway.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("registry lock delayed native security expiry")
	}
	if err := f.store.Close(); !errors.Is(err, controlstate.ErrInstanceInUse) {
		t.Fatal("pending cleanup lost ownership", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := bound.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Close blocked on registry lock instead of its context", err)
	}
	once.Do(func() { close(unblock) })
	if err := await(t, persisted); !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal("expected uncertain publication", err)
	}
	await(t, bound.Done())
	if !errors.Is(bound.Err(), sessionstate.ErrSecurity) {
		t.Fatal("lost security expiry cause", bound.Err())
	}
}
