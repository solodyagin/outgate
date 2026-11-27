package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

func registrationChange(t *testing.T, s *Store) Change {
	t.Helper()
	rev, err := s.Revision(t.Context())
	must(t, err)
	return change(t, rev)
}
func registrationGrant(t *testing.T, s *Store, generation uint64, instance string) (IssuedGrant, GrantPeer, v1.Register) {
	t.Helper()
	b := binding()
	b.CredentialGeneration = generation
	b.InstanceID = instance
	issued, err := s.IssueGrant(t.Context(), registrationChange(t, s), b)
	must(t, err)
	p := peer()
	p.InstanceID = instance
	r := registration(b)
	if generation == 0 {
		r.CredentialGeneration = nil
	}
	return issued, p, r
}

func TestRegistrationOwnershipGenerationAndReconnect(t *testing.T) {
	config := securityConfig(t)
	s := fixture(t, config)
	old, p, reg := registrationGrant(t, s, 7, "reports-1")
	lease, err := s.AcquireRegistration(t.Context(), old.DeploymentGrant, p, reg)
	must(t, err)
	if _, err := s.AcquireRegistration(t.Context(), old.DeploymentGrant, p, reg); !errors.Is(err, ErrInstanceInUse) {
		t.Fatal("duplicate owner admitted", err)
	}
	if err := s.Close(); !errors.Is(err, ErrInstanceInUse) {
		t.Fatal("active owner allowed closing control state", err)
	}
	if other, err := Open(t.Context(), config); err == nil {
		_ = other.Close()
		t.Fatal("active ownership lost OS lock")
	}
	// Mutation of the returned metadata cannot change the lease identity.
	lease.Grant.GrantID = "changed"
	_, err = lease.Check(t.Context())
	must(t, err)
	newer, np, nr := registrationGrant(t, s, 8, "reports-1")
	if _, err := s.AcquireRegistration(t.Context(), newer.DeploymentGrant, np, nr); !errors.Is(err, ErrInstanceInUse) {
		t.Fatal("rotation bypassed old cleanup", err)
	}
	_, err = s.GrantForPeer(t.Context(), old.Record.GrantID, p)
	must(t, err)
	lease.Release()
	lease.Release()
	next, err := s.AcquireRegistration(t.Context(), newer.DeploymentGrant, np, nr)
	must(t, err)
	lease.Release() // stale cleanup must not remove the new owner
	if _, err := s.AcquireRegistration(t.Context(), newer.DeploymentGrant, np, nr); !errors.Is(err, ErrInstanceInUse) {
		t.Fatal("stale release removed new owner", err)
	}
	if _, err := s.GrantForPeer(t.Context(), old.Record.GrantID, p); !errors.Is(err, ErrDenied) {
		t.Fatal("old generation usable over HTTPS", err)
	}
	if _, err := s.VerifyDeploymentGrant(t.Context(), old.DeploymentGrant, p, reg); !errors.Is(err, ErrDenied) {
		t.Fatal("old generation reauthenticated", err)
	}
	next.Release()
	reconnect, err := s.AcquireRegistration(t.Context(), newer.DeploymentGrant, np, nr)
	must(t, err)
	reconnect.Release()
	must(t, s.Close())
	reopened, err := Open(t.Context(), config)
	must(t, err)
	defer reopened.Close()
	if _, err := reopened.AcquireRegistration(t.Context(), old.DeploymentGrant, p, reg); !errors.Is(err, ErrDenied) {
		t.Fatal("restart reset generation fence", err)
	}
	same, err := reopened.AcquireRegistration(t.Context(), newer.DeploymentGrant, np, nr)
	must(t, err)
	same.Release()
	different, dp, dr := registrationGrant(t, reopened, 8, "reports-1")
	if _, err := reopened.AcquireRegistration(t.Context(), different.DeploymentGrant, dp, dr); !errors.Is(err, ErrDenied) {
		t.Fatal("same generation changed credential pair", err)
	}
	static, sp, sr := registrationGrant(t, reopened, 0, "reports-1")
	if _, err := reopened.AcquireRegistration(t.Context(), static.DeploymentGrant, sp, sr); !errors.Is(err, ErrDenied) {
		t.Fatal("static credential bypassed generation fence", err)
	}
}

func TestRegistrationConcurrentOwnerAndOutboxRollback(t *testing.T) {
	s := fixture(t, securityConfig(t))
	issued, p, reg := registrationGrant(t, s, 7, "reports-1")
	var group sync.WaitGroup
	winners := make(chan *RegistrationLease, 20)
	failures := make(chan error, 20)
	for range 20 {
		group.Go(func() {
			lease, err := s.AcquireRegistration(t.Context(), issued.DeploymentGrant, p, reg)
			if err == nil {
				winners <- lease
			} else {
				failures <- err
			}
		})
	}
	group.Wait()
	close(winners)
	close(failures)
	count := 0
	for lease := range winners {
		count++
		lease.Release()
	}
	if count != 1 {
		t.Fatal("concurrent registration admitted multiple owners", count)
	}
	for err := range failures {
		if !errors.Is(err, ErrInstanceInUse) {
			t.Fatal(err)
		}
	}
	config := securityConfig(t)
	config.MaxOutboxEvents = 1
	limited := fixture(t, config)
	issued, p, reg = registrationGrant(t, limited, 7, "reports-1")
	if _, err := limited.AcquireRegistration(t.Context(), issued.DeploymentGrant, p, reg); !errors.Is(err, ErrOutboxFull) {
		t.Fatal("outbox failure accepted registration", err)
	}
	var rows int
	must(t, limited.db.QueryRowContext(t.Context(), "SELECT count(*) FROM registration_generations").Scan(&rows))
	if rows != 0 {
		t.Fatal("failed admission persisted generation")
	}
	events, err := limited.Events(t.Context(), 0, 1)
	must(t, err)
	must(t, limited.Acknowledge(t.Context(), events[0].OperationID))
	lease, err := limited.AcquireRegistration(t.Context(), issued.DeploymentGrant, p, reg)
	must(t, err)
	lease.Release()
	must(t, limited.Close())
}

func TestRegistrationQuotaRevocationAndUint64Fence(t *testing.T) {
	config := securityConfig(t)
	config.MaxRegistrations = 1
	s := fixture(t, config)
	first, p, r := registrationGrant(t, s, math.MaxUint64, "reports-1")
	lease, err := s.AcquireRegistration(t.Context(), first.DeploymentGrant, p, r)
	must(t, err)
	second, p2, r2 := registrationGrant(t, s, 0, "reports-2")
	if _, err := s.AcquireRegistration(t.Context(), second.DeploymentGrant, p2, r2); !errors.Is(err, ErrUnavailable) {
		t.Fatal("active owner budget exceeded", err)
	}
	c := registrationChange(t, s)
	_, err = s.Revoke(t.Context(), Command{OperationID: c.OperationID, Actor: c.Actor, ExpectedRevision: c.ExpectedRevision, Reason: c.Reason, Target: Target{Kind: "grant_id", ServiceID: p.ServiceID, Value: first.Record.GrantID}})
	must(t, err)
	if _, err := lease.Check(t.Context()); !errors.Is(err, ErrDenied) {
		t.Fatal("lease ignored durable revoke", err)
	}
	lease.Release()
	next, err := s.AcquireRegistration(t.Context(), second.DeploymentGrant, p2, r2)
	must(t, err)
	next.Release()
	if _, err := s.AcquireRegistration(t.Context(), second.DeploymentGrant+"bad", p2, r2); !errors.Is(err, ErrDenied) {
		t.Fatal("invalid credential reserved owner", err)
	}
}

func TestRegistrationCheckpointSurvivesAbruptExit(t *testing.T) {
	type request struct {
		Credential string
		Peer       GrantPeer
		Register   v1.Register
	}
	if os.Getenv("OUTGATE_REGISTRATION_EXIT") == "1" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			os.Exit(1)
		}
		var input request
		if json.Unmarshal(data, &input) != nil {
			os.Exit(2)
		}
		c := Config{Path: os.Getenv("OUTGATE_REGISTRATION_DB"), Epoch: [32]byte{1}, Services: map[string][]string{"reports": {"/api"}}}
		store, err := Open(context.Background(), c)
		if err != nil {
			os.Exit(3)
		}
		if _, err := store.AcquireRegistration(context.Background(), input.Credential, input.Peer, input.Register); err != nil {
			os.Exit(4)
		}
		os.Exit(0) // no lease release, DB close or delivery of register_ack
	}
	config := securityConfig(t)
	s := fixture(t, config)
	old, op, or := registrationGrant(t, s, 7, "reports-1")
	newer, p, r := registrationGrant(t, s, 9, "reports-1")
	must(t, s.Close())
	data, err := json.Marshal(request{newer.DeploymentGrant, p, r})
	must(t, err)
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRegistrationCheckpointSurvivesAbruptExit$")
	child.Env = append(os.Environ(), "OUTGATE_REGISTRATION_EXIT=1", "OUTGATE_REGISTRATION_DB="+config.Path)
	child.Stdin = strings.NewReader(string(data))
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("admission exit failed: %v (%s)", err, output)
	}
	reopened, err := Open(t.Context(), config)
	must(t, err)
	defer reopened.Close()
	if _, err := reopened.AcquireRegistration(t.Context(), old.DeploymentGrant, op, or); !errors.Is(err, ErrDenied) {
		t.Fatal("process exit lost high-water fence", err)
	}
	lease, err := reopened.AcquireRegistration(t.Context(), newer.DeploymentGrant, p, r)
	must(t, err)
	lease.Release()
	events, err := reopened.Events(t.Context(), 0, 200)
	must(t, err)
	for _, event := range events {
		if event.Action == "registration_admitted" {
			if event.Target.Value != newer.Record.GrantID {
				t.Fatal("wrong admitted grant event")
			}
		}
	}
}
