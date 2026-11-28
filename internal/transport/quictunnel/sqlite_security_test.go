package quictunnel

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate/internal/controlstate"
)

func TestSQLiteSecurityRenewsRealHealthyWarmupAndRejectsStoreLoss(t *testing.T) {
	f := durableAdmissionFixture(t)
	config := replay.SQLiteConfig{Path: filepath.Join(t.TempDir(), "gateway-replay.db"), Namespace: "outgate:gateway", Epoch: [32]byte{8}, Capacity: 200, CallerCapacity: 100, AdmittedRPS: 1}
	must(t, replay.InitializeSQLite(t.Context(), config))
	store, err := replay.OpenSQLite(t.Context(), config)
	must(t, err)
	t.Cleanup(func() { must(t, store.Close()) })
	source, err := SQLiteAdmissionSecurity(f.store, store)
	must(t, err)
	health, err := source(t.Context())
	must(t, err)
	if !health.ReadyNotBefore.After(time.Now()) {
		t.Fatal("missing replay warmup")
	}
	if err := store.Ready(t.Context()); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatal("warming store became ready", err)
	}
	var checks atomic.Int32
	f.config.Renewal = SecurityRenewal{Interval: 20 * time.Millisecond, Timeout: time.Second}
	f.config.Security = func(ctx context.Context) (AdmissionSecurity, error) {
		checks.Add(1)
		state, err := source(ctx)
		if err == nil {
			state.ValidUntil = minTime(state.ValidUntil, time.Now().Add(4*time.Second))
		}
		return state, err
	}
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	bound, _, ack, openErr, acceptErr := f.open(t, a)
	must(t, openErr)
	must(t, acceptErr)
	must(t, bound.RenewSecurity(true, time.Now().Add(time.Second)))
	eventually(t, func() bool { return checks.Load() >= 65 })
	if !bound.Snapshot().TransportActive || bound.Snapshot().Phase != sessionstate.Registered || ack.ReadyNotBefore < health.ReadyNotBefore.Unix() {
		t.Fatal("healthy warmup was bypassed or killed")
	}
	if err := store.Ready(t.Context()); !errors.Is(err, httpsig.ErrReplayUnavailable) {
		t.Fatal("renewal lifted replay barrier", err)
	}
	must(t, store.Close())
	await(t, bound.Done())
	if !errors.Is(bound.Err(), sessionstate.ErrSecurity) {
		t.Fatal("broken replay ignored during warmup", bound.Err())
	}
	must(t, f.store.Close())
}

func TestSQLiteSecurityRequiresProvisionedStores(t *testing.T) {
	if _, err := SQLiteAdmissionSecurity(nil, nil); !errors.Is(err, controlstate.ErrConfig) {
		t.Fatal("missing stores accepted")
	}
}
