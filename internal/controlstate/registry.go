package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
)

var ErrRegistryUninitialized = fmt.Errorf("%w: registry requires explicit bootstrap", ErrUnavailable)

const registryAction = "registry_committed"

// RegistryCommit is safe operation metadata, not a live publication receipt.
// Revision is the installation-wide control revision. RegistryRevision is the
// registry's separate mutation counter; other security mutations do not change it.
type RegistryCommit struct {
	Revision         uint64 `json:"revision,string"`
	RegistryRevision uint64 `json:"registry_revision,string"`
	Digest           string `json:"sha256"`
}

type RegistrySnapshot struct {
	Data     []byte
	Commit   RegistryCommit
	Revision uint64 // current control revision, including later security changes
}

// CommitRegistry atomically persists a validated candidate, operation and audit
// event. The caller must authenticate/authorize the full mutation, serialize
// candidate creation and live publication, and close readiness on uncertainty.
// No grant check or registry mutation is performed here. nil expected means
// explicit first bootstrap (only an empty revision-0 registry is permitted);
// otherwise both the control CAS and registry CAS must match, and the candidate
// must represent exactly one next registry revision. Recheck current actor scope
// even for retries; a committed retry returns its original safe result.
func (s *Store) CommitRegistry(ctx context.Context, c Change, config registry.Config, data []byte, expected *uint64) (RegistryCommit, error) {
	return s.commitRegistry(ctx, c, config, data, expected, nil)
}

func (s *Store) commitRegistry(ctx context.Context, c Change, config registry.Config, data []byte, expected *uint64, authorize func(*sql.Tx) error) (RegistryCommit, error) {
	if s.version < 4 || len(data) == 0 || len(data) > registry.MaxSnapshotBytes || !s.registryConfigMatches(config) {
		return RegistryCommit{}, ErrConfig
	}
	data = bytes.Clone(data)
	candidate, err := registry.RestoreSnapshot(config, data)
	if err != nil {
		return RegistryCommit{}, ErrConfig
	}
	request := struct {
		Action    string
		Change    Change
		Digest    string
		Bootstrap bool
		Expected  uint64
	}{Action: registryAction, Change: c, Digest: fmtDigest(sha256.Sum256(data)), Bootstrap: expected == nil}
	if expected != nil {
		request.Expected = *expected
		if request.Expected == math.MaxUint64 || candidate.Revision() != request.Expected+1 {
			return RegistryCommit{}, ErrConflict
		}
	} else if candidate.Revision() != 0 {
		return RegistryCommit{}, ErrConfig
	}
	encoded, _, err := s.securityMutation(ctx, c, registryAction, request, func(tx *sql.Tx, next uint64, _ time.Time) ([]byte, Target, error) {
		if authorize != nil {
			if err := authorize(tx); err != nil {
				return nil, Target{}, err
			}
		}
		previous, committed, err := s.readRegistry(ctx, tx, next-1)
		if err != nil {
			return nil, Target{}, err
		}
		if request.Bootstrap {
			if len(previous) != 0 {
				return nil, Target{}, ErrConflict
			}
		} else {
			if len(previous) == 0 {
				return nil, Target{}, ErrRegistryUninitialized
			}
			old, err := registry.RestoreSnapshot(config, previous)
			if err != nil || old.Revision() != committed.RegistryRevision {
				return nil, Target{}, ErrUnavailable
			}
			if old.Revision() != request.Expected {
				return nil, Target{}, ErrConflict
			}
		}
		updated, err := tx.ExecContext(ctx, "UPDATE registry_snapshot SET operation_id=?,revision=?,payload=? WHERE id=1", c.OperationID, strconv.FormatUint(next, 10), data)
		if err != nil {
			return nil, Target{}, ErrUnavailable
		}
		if count, err := updated.RowsAffected(); err != nil || count != 1 {
			return nil, Target{}, ErrUnavailable
		}
		result, err := json.Marshal(RegistryCommit{next, candidate.Revision(), request.Digest})
		return result, Target{}, err
	})
	if err != nil {
		return RegistryCommit{}, err
	}
	result, err := decodeRegistryCommit(encoded)
	if err != nil || result.Digest != request.Digest || result.RegistryRevision != candidate.Revision() {
		return RegistryCommit{}, ErrUnavailable
	}
	return result, nil
}

// LoadRegistry reads one consistent control snapshot. minimumRevision is an
// independently retained control watermark; it must not be learned from a
// backup being checked. Zero supplies no rollback proof. Epoch and this floor
// cannot prove freshness if an entire installation and its external evidence
// are rolled back together. Restoring the returned Data is cold recovery only.
func (s *Store) LoadRegistry(ctx context.Context, config registry.Config, minimumRevision uint64) (RegistrySnapshot, error) {
	if s.version < 4 || !s.registryConfigMatches(config) {
		return RegistrySnapshot{}, ErrConfig
	}
	conn, err := s.connection(ctx)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return RegistrySnapshot{}, ErrUnavailable
	}
	defer tx.Rollback()
	revision, err := s.metadata(ctx, tx)
	if err != nil || revision < minimumRevision {
		return RegistrySnapshot{}, ErrUnavailable
	}
	data, committed, err := s.readRegistry(ctx, tx, revision)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	if len(data) == 0 {
		return RegistrySnapshot{}, ErrRegistryUninitialized
	}
	restored, err := registry.RestoreSnapshot(config, data)
	if err != nil || restored.Revision() != committed.RegistryRevision {
		return RegistrySnapshot{}, ErrUnavailable
	}
	if err := s.checkFiles(); err != nil {
		return RegistrySnapshot{}, err
	}
	return RegistrySnapshot{Data: data, Commit: committed, Revision: revision}, nil
}

// readRegistry checks the sentinel or the latest registry operation binding.
// CASE guards bound every stored value before the driver allocates a result.
// Keep the latest registry operation/result when adding operation retention.
func (s *Store) readRegistry(ctx context.Context, q queryer, revision uint64) ([]byte, RegistryCommit, error) {
	fail := func() ([]byte, RegistryCommit, error) { return nil, RegistryCommit{}, ErrUnavailable }
	var operation, stamp string
	var data []byte
	if q.QueryRowContext(ctx, `SELECT CASE WHEN length(operation_id)<=36 THEN operation_id ELSE NULL END,CASE WHEN length(revision)<=20 THEN revision ELSE NULL END,CASE WHEN length(payload)<=1048576 THEN payload ELSE NULL END FROM registry_snapshot WHERE id=1`).Scan(&operation, &stamp, &data) != nil {
		return fail()
	}
	var latest string
	err := q.QueryRowContext(ctx, `SELECT CASE WHEN length(o.id)<=36 THEN o.id ELSE NULL END FROM control_operations o JOIN security_results r ON r.id=o.id WHERE r.action=? ORDER BY length(o.revision) DESC,o.revision DESC LIMIT 1`, registryAction).Scan(&latest)
	if operation == "" && stamp == "0" && len(data) == 0 && errors.Is(err, sql.ErrNoRows) {
		return nil, RegistryCommit{}, nil // explicit provisioning/upgrade sentinel
	}
	if err != nil || latest != operation || len(data) == 0 {
		return fail()
	}
	number, err := strconv.ParseUint(stamp, 10, 64)
	if err != nil || number == 0 || number > revision || strconv.FormatUint(number, 10) != stamp {
		return fail()
	}
	var encoded []byte
	if q.QueryRowContext(ctx, `SELECT CASE WHEN length(r.result)<=1024 THEN r.result ELSE NULL END FROM security_results r JOIN control_operations o ON o.id=r.id WHERE r.id=? AND r.action=? AND o.revision=?`, operation, registryAction, stamp).Scan(&encoded) != nil {
		return fail()
	}
	committed, err := decodeRegistryCommit(encoded)
	if err != nil || committed.Revision != number || committed.Digest != fmtDigest(sha256.Sum256(data)) {
		return fail()
	}
	return data, committed, nil
}

func decodeRegistryCommit(data []byte) (RegistryCommit, error) {
	var result RegistryCommit
	if len(data) == 0 || len(data) > 1024 || json.Unmarshal(data, &result) != nil || result.Revision < 2 || result.RegistryRevision > result.Revision-2 ||
		!(Target{Kind: "spki_sha256", ServiceID: "audit", Value: result.Digest}).valid() {
		return RegistryCommit{}, ErrUnavailable
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(data, canonical) {
		return RegistryCommit{}, ErrUnavailable
	}
	return result, nil
}

func (s *Store) registryConfigMatches(config registry.Config) bool {
	if len(config.Services) != len(s.config.Services) || config.FrontendService != s.config.RootFrontend {
		return false
	}
	for id, service := range config.Services {
		allowed, found := s.config.Services[id]
		if !found || len(service.AllowedPaths) != len(allowed) {
			return false
		}
		paths := make([]string, len(service.AllowedPaths))
		for i, path := range service.AllowedPaths {
			var err error
			paths[i], err = v1.NormalizePrefix(path)
			if err != nil {
				return false
			}
		}
		slices.Sort(paths)
		if !slices.Equal(paths, allowed) {
			return false
		}
	}
	return true
}
