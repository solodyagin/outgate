package controlstate

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func configuration(t *testing.T) Config {
	t.Helper()
	return Config{Path: filepath.Join(t.TempDir(), "control.db"), Epoch: [32]byte{1}}
}
func fixture(t *testing.T, config Config) *Store {
	t.Helper()
	must(t, Initialize(t.Context(), config))
	store, err := Open(t.Context(), config)
	must(t, err)
	t.Cleanup(func() { must(t, store.Close()) })
	return store
}
func command(t *testing.T, target Target, revision uint64) Command {
	t.Helper()
	id, err := uuid.NewV7()
	must(t, err)
	return Command{OperationID: id.String(), Actor: "admin-1", ExpectedRevision: revision, Target: target, Reason: "compromised credential"}
}
func assertRevision(t *testing.T, s *Store, want uint64) {
	t.Helper()
	got, err := s.Revision(t.Context())
	must(t, err)
	if got != want {
		t.Fatalf("revision %d, want %d", got, want)
	}
}

func TestRevokeCommitRestartRetryAndAudit(t *testing.T) {
	config := configuration(t)
	s := fixture(t, config)
	target := Target{Kind: "grant_id", ServiceID: "reports", Value: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
	cmd := command(t, target, 1)
	before, err := s.IsRevoked(t.Context(), target)
	must(t, err)
	if before {
		t.Fatal("new target revoked")
	}
	original, err := s.Revoke(t.Context(), cmd)
	must(t, err)
	assertRevision(t, s, 2)
	// The same committed key wins over its old expected revision.
	repeated, err := s.Revoke(t.Context(), cmd)
	must(t, err)
	if !reflect.DeepEqual(original, repeated) {
		t.Fatal("retry changed result")
	}
	for _, change := range []func(*Command){func(c *Command) { c.Actor = "another-admin" }, func(c *Command) { c.Reason = "different" }, func(c *Command) { c.ExpectedRevision = 2 }, func(c *Command) { c.Target.ServiceID = "other" }} {
		modified := cmd
		change(&modified)
		if _, err := s.Revoke(t.Context(), modified); !errors.Is(err, ErrConflict) {
			t.Fatal("operation key reuse accepted", err)
		}
	}
	events, err := s.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 1 || events[0].OperationID != cmd.OperationID || events[0].Revision != "2" || events[0].Target != target {
		t.Fatal("incorrect atomic outbox", events)
	}
	must(t, s.Close())
	reopened, err := Open(t.Context(), config)
	must(t, err)
	defer reopened.Close()
	revoked, err := reopened.IsRevoked(t.Context(), target)
	must(t, err)
	if !revoked {
		t.Fatal("restart lost revocation")
	}
	repeated, err = reopened.Revoke(t.Context(), cmd)
	must(t, err)
	if !reflect.DeepEqual(original, repeated) {
		t.Fatal("restart lost operation result")
	}
	for range 2 {
		must(t, reopened.Acknowledge(t.Context(), cmd.OperationID))
	}
	events, err = reopened.Events(t.Context(), 0, 1)
	must(t, err)
	if len(events) != 0 {
		t.Fatal("ack retained event")
	}
	assertRevision(t, reopened, 2)
	repeated, err = reopened.Revoke(t.Context(), cmd)
	must(t, err)
	if repeated.Revision != 2 {
		t.Fatal("ack discarded dedup result")
	}
}

func TestServiceRevocationAndConcurrentRevision(t *testing.T) {
	s := fixture(t, configuration(t))
	targets := []Target{{Kind: "service", ServiceID: "reports"}, {Kind: "hmac_key_id", ServiceID: "other", Value: "key-1"}}
	var group sync.WaitGroup
	results := make(chan error, 2)
	for _, target := range targets {
		cmd := command(t, target, 1)
		group.Go(func() { _, err := s.Revoke(t.Context(), cmd); results <- err })
	}
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("revision race admitted both updates")
	}
	assertRevision(t, s, 2)
	// Commit a service-wide target if the other operation won the race.
	service := targets[0]
	revoked, err := s.IsRevoked(t.Context(), service)
	must(t, err)
	if !revoked {
		_, err = s.Revoke(t.Context(), command(t, service, 2))
		must(t, err)
	}
	for _, target := range []Target{{Kind: "spki_sha256", ServiceID: "reports", Value: strings.Repeat("a", 64)}, {Kind: "certificate_serial", ServiceID: "reports", Value: "71ab"}, {Kind: "hmac_key_id", ServiceID: "reports", Value: "new-key"}} {
		revoked, err := s.IsRevoked(t.Context(), target)
		must(t, err)
		if !revoked {
			t.Fatal("service revocation missed credential", target.Kind)
		}
		target.ServiceID = "unrelated"
		revoked, err = s.IsRevoked(t.Context(), target)
		must(t, err)
		if revoked {
			t.Fatal("revocation escaped service scope")
		}
	}
}

func TestOutboxFailureAndCapacityNeverPublishPartialState(t *testing.T) {
	for _, mode := range []string{"count", "bytes", "insert-error"} {
		t.Run(mode, func(t *testing.T) {
			config := configuration(t)
			if mode == "count" {
				config.MaxOutboxEvents = 1
			}
			if mode == "bytes" {
				config.MaxOutboxBytes = 1
			}
			s := fixture(t, config)
			target := Target{Kind: "service", ServiceID: "first"}
			expected := uint64(1)
			var committed Command
			if mode == "count" {
				committed = command(t, target, 1)
				_, err := s.Revoke(t.Context(), committed)
				must(t, err)
				expected = 2
			}
			if mode == "insert-error" {
				_, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER reject_audit BEFORE INSERT ON control_outbox BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`)
				must(t, err)
			}
			target.ServiceID = "second"
			_, err := s.Revoke(t.Context(), command(t, target, expected))
			want := ErrOutboxFull
			if mode == "insert-error" {
				want = ErrUnavailable
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
			assertRevision(t, s, expected)
			revoked, err := s.IsRevoked(t.Context(), target)
			must(t, err)
			if revoked {
				t.Fatal("failed audit published revocation")
			}
			var count int
			must(t, s.db.QueryRowContext(t.Context(), "SELECT count(*) FROM control_operations").Scan(&count))
			if count != int(expected-1) {
				t.Fatal("failed audit retained operation")
			}
			if mode == "count" {
				// Dedup still succeeds with a full outbox, without generating another event.
				_, err := s.Revoke(t.Context(), committed)
				must(t, err)
				must(t, s.Acknowledge(t.Context(), committed.OperationID))
				_, err = s.Revoke(t.Context(), command(t, target, expected))
				must(t, err)
			}
		})
	}
}

func TestControlRejectsMissingEpochSchemaAndCorruption(t *testing.T) {
	config := configuration(t)
	if _, err := Open(t.Context(), config); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing state opened", err)
	}
	s := fixture(t, config)
	if err := Initialize(t.Context(), config); !errors.Is(err, ErrUnavailable) {
		t.Fatal("initialization overwrote state")
	}
	must(t, s.Close())
	wrong := config
	wrong.Epoch[0]++
	if _, err := Open(t.Context(), wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong epoch opened", err)
	}
	s, err := Open(t.Context(), config)
	must(t, err)
	_, err = s.db.ExecContext(t.Context(), "UPDATE control_metadata SET revision='01'")
	must(t, err)
	if _, err := s.Revision(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("noncanonical revision accepted", err)
	}
	must(t, s.Close())
	if _, err := Open(t.Context(), config); !errors.Is(err, ErrUnavailable) {
		t.Fatal("corrupt metadata opened", err)
	}
	for _, missing := range []string{"-wal", ".owner"} {
		t.Run("missing"+missing, func(t *testing.T) {
			config := configuration(t)
			store := fixture(t, config)
			must(t, store.Close())
			must(t, os.Remove(config.Path+missing))
			if _, err := Open(t.Context(), config); !errors.Is(err, ErrUnavailable) {
				t.Fatal("missing file regenerated", err)
			}
		})
	}
}

func TestUint64RevisionsAndBoundedOutbox(t *testing.T) {
	s := fixture(t, configuration(t))
	start := uint64(math.MaxUint64 - 1)
	_, err := s.db.ExecContext(t.Context(), "UPDATE control_metadata SET revision=?", strconv.FormatUint(start, 10))
	must(t, err)
	result, err := s.Revoke(t.Context(), command(t, Target{Kind: "service", ServiceID: "last"}, start))
	must(t, err)
	if result.Revision != math.MaxUint64 {
		t.Fatal("uint64 truncated")
	}
	events, err := s.Events(t.Context(), start, 1)
	must(t, err)
	if len(events) != 1 || events[0].Revision != "18446744073709551615" {
		t.Fatal("uint64 cursor lost event", events)
	}
	if _, err := s.Revoke(t.Context(), command(t, Target{Kind: "service", ServiceID: "overflow"}, math.MaxUint64)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("revision wrapped", err)
	}
	for _, limit := range []int{0, 201} {
		if _, err := s.Events(t.Context(), 0, limit); !errors.Is(err, ErrConfig) {
			t.Fatal("unbounded events accepted")
		}
	}
}

func TestControlSingleOwnerAcrossProcesses(t *testing.T) {
	if os.Getenv("OUTGATE_CONTROL_LOCK_HELPER") == "1" {
		store, err := Open(context.Background(), Config{Path: os.Getenv("OUTGATE_CONTROL_LOCK_PATH"), Epoch: [32]byte{1}})
		if err == nil {
			_ = store.Close()
			os.Exit(1)
		}
		if !errors.Is(err, ErrUnavailable) {
			os.Exit(2)
		}
		os.Exit(0)
	}
	config := configuration(t)
	s := fixture(t, config)
	if other, err := Open(t.Context(), config); err == nil {
		_ = other.Close()
		t.Fatal("second in-process owner admitted")
	}
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestControlSingleOwnerAcrossProcesses$")
	child.Env = append(os.Environ(), "OUTGATE_CONTROL_LOCK_HELPER=1", "OUTGATE_CONTROL_LOCK_PATH="+config.Path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("owner isolation failed: %v (%s)", err, output)
	}
	must(t, s.Close())
	next, err := Open(t.Context(), config)
	must(t, err)
	must(t, next.Close())
}

func TestCommandValidation(t *testing.T) {
	now := time.Now()
	c := command(t, Target{Kind: "service", ServiceID: "reports"}, 1)
	for _, change := range []func(*Command){
		func(c *Command) { c.OperationID = uuid.NewString() }, func(c *Command) { c.Actor = "" }, func(c *Command) { c.ExpectedRevision = 0 },
		func(c *Command) { c.Reason = strings.Repeat("x", 513) }, func(c *Command) { c.Target.Kind = "unknown" }, func(c *Command) { c.Target.Value = "unexpected" },
		func(c *Command) { c.Target.ServiceID = "bad/service" },
		func(c *Command) {
			id, _ := uuid.Parse(c.OperationID)
			timestamp := uint64(now.Add(-31 * 24 * time.Hour).UnixMilli())
			var bytes [8]byte
			binary.BigEndian.PutUint64(bytes[:], timestamp)
			copy(id[:6], bytes[2:])
			c.OperationID = id.String()
		},
		func(c *Command) {
			id, _ := uuid.Parse(c.OperationID)
			timestamp := uint64(now.Add(time.Minute).UnixMilli())
			var bytes [8]byte
			binary.BigEndian.PutUint64(bytes[:], timestamp)
			copy(id[:6], bytes[2:])
			c.OperationID = id.String()
		},
	} {
		changed := c
		change(&changed)
		if changed.valid(now) {
			t.Fatal("invalid command accepted", changed.Target.Kind)
		}
	}
	for _, target := range []Target{{Kind: "spki_sha256", ServiceID: "reports", Value: strings.Repeat("A", 64)}, {Kind: "grant_id", ServiceID: "reports", Value: "not-a-grant"}, {Kind: "certificate_serial", ServiceID: "reports", Value: "bad\nserial"}} {
		if target.valid() {
			t.Fatal("invalid target accepted")
		}
	}
}

func TestOwnerLockOutlivesInflightConnection(t *testing.T) {
	config := configuration(t)
	s := fixture(t, config)
	held, err := s.connection(t.Context())
	must(t, err)
	closing, done := make(chan struct{}), make(chan error, 1)
	go func() { close(closing); done <- s.Close() }()
	<-closing
	if other, err := Open(t.Context(), config); err == nil {
		_ = other.Close()
		t.Fatal("Close released owner while operation in flight")
	}
	select {
	case <-done:
		t.Fatal("Close did not wait for operation")
	default:
	}
	must(t, held.Close())
	must(t, <-done)
	next, err := Open(t.Context(), config)
	must(t, err)
	must(t, next.Close())
	if _, err := s.Revision(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed store allowed reads", err)
	}
}

func TestOutboxCursorUsesNumericRevisionOrder(t *testing.T) {
	s := fixture(t, configuration(t))
	_, err := s.db.ExecContext(t.Context(), "UPDATE control_metadata SET revision='8'")
	must(t, err)
	for revision := uint64(8); revision < 11; revision++ {
		_, err = s.Revoke(t.Context(), command(t, Target{Kind: "service", ServiceID: "service-" + strconv.FormatUint(revision, 10)}, revision))
		must(t, err)
	}
	events, err := s.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 3 || events[0].Revision != "9" || events[1].Revision != "10" || events[2].Revision != "11" {
		t.Fatal("lexicographic order mixed revisions", events)
	}
	events, err = s.Events(t.Context(), 9, 1)
	must(t, err)
	if len(events) != 1 || events[0].Revision != "10" {
		t.Fatal("cursor skipped numeric successor", events)
	}
}

func TestOwnerReplacementDeniesReadAndCommit(t *testing.T) {
	config := configuration(t)
	s := fixture(t, config)
	if err := os.Rename(config.Path+".owner", config.Path+".owner-old"); err != nil {
		t.Skip("OS prevents renaming live owner handle")
	}
	must(t, os.WriteFile(config.Path+".owner", nil, 0600))
	if _, err := s.Revision(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replaced owner allowed snapshot", err)
	}
	target := Target{Kind: "service", ServiceID: "reports"}
	if _, err := s.Revoke(t.Context(), command(t, target, 1)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replaced owner allowed commit", err)
	}
	if _, err := s.IsRevoked(t.Context(), target); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replaced owner allowed security read", err)
	}
}

func TestCommittedRevocationSurvivesAbruptProcessExit(t *testing.T) {
	if os.Getenv("OUTGATE_CONTROL_CRASH_HELPER") == "1" {
		s, err := Open(context.Background(), Config{Path: os.Getenv("OUTGATE_CONTROL_CRASH_PATH"), Epoch: [32]byte{1}})
		if err != nil {
			os.Exit(1)
		}
		id, err := uuid.NewV7()
		if err != nil {
			os.Exit(2)
		}
		_, err = s.Revoke(context.Background(), Command{OperationID: id.String(), Actor: "admin-1", ExpectedRevision: 1, Target: Target{Kind: "service", ServiceID: "reports"}, Reason: "compromised credential"})
		if err != nil {
			os.Exit(3)
		}
		os.Exit(0) // intentionally bypass Store.Close and all Go deferred cleanup
	}
	config := configuration(t)
	must(t, Initialize(t.Context(), config))
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCommittedRevocationSurvivesAbruptProcessExit$")
	child.Env = append(os.Environ(), "OUTGATE_CONTROL_CRASH_HELPER=1", "OUTGATE_CONTROL_CRASH_PATH="+config.Path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("abrupt-exit helper failed: %v (%s)", err, output)
	}
	s, err := Open(t.Context(), config)
	must(t, err)
	defer s.Close()
	assertRevision(t, s, 2)
	target := Target{Kind: "service", ServiceID: "reports"}
	revoked, err := s.IsRevoked(t.Context(), target)
	must(t, err)
	if !revoked {
		t.Fatal("process exit lost committed revocation")
	}
	events, err := s.Events(t.Context(), 0, 1)
	must(t, err)
	if len(events) != 1 {
		t.Fatal("process exit lost committed outbox")
	}
	retried, err := s.Revoke(t.Context(), Command{OperationID: events[0].OperationID, Actor: events[0].Actor, ExpectedRevision: 1, Target: target, Reason: events[0].Reason})
	must(t, err)
	if retried.Revision != 2 {
		t.Fatal("process exit lost committed operation result")
	}
}
