package controlstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// ReplaceAccess replaces the global access snapshot. The caller must validate
// current global security-admin scope/MFA on every call, and a bound unused
// preview for a new operation. Committed retries do not require a new preview.
// This is not a scoped Admin API implementation or a route-registration grant.
func (s *Store) ReplaceAccess(ctx context.Context, c Change, snapshot AccessSnapshot) (uint64, error) {
	snapshot, err := s.accessSnapshot(snapshot)
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > maxSecurityDocument {
		return 0, ErrConfig
	}
	request := struct {
		Action   string
		Change   Change
		Snapshot AccessSnapshot
	}{"access_replaced", c, snapshot}
	encoded, _, err := s.securityMutation(ctx, c, "access_replaced", request, func(tx *sql.Tx, revision uint64, _ time.Time) ([]byte, Target, error) {
		updated, err := tx.ExecContext(ctx, "UPDATE access_snapshot SET payload=? WHERE id=1", data)
		if err != nil {
			return nil, Target{}, ErrUnavailable
		}
		if count, err := updated.RowsAffected(); err != nil || count != 1 {
			return nil, Target{}, ErrUnavailable
		}
		result, err := json.Marshal(struct {
			Revision uint64 `json:"revision,string"`
		}{revision})
		return result, Target{}, err
	})
	if err != nil {
		return 0, err
	}
	var result struct {
		Revision uint64 `json:"revision,string"`
	}
	if json.Unmarshal(encoded, &result) != nil || result.Revision == 0 {
		return 0, ErrUnavailable
	}
	return result.Revision, nil
}

func (s *Store) readAccess(ctx context.Context, q queryer) (AccessSnapshot, error) {
	var encoded []byte
	if q.QueryRowContext(ctx, "SELECT CASE WHEN length(payload)<=1048576 THEN payload ELSE NULL END FROM access_snapshot WHERE id=1").Scan(&encoded) != nil || len(encoded) == 0 {
		return AccessSnapshot{}, ErrUnavailable
	}
	var snapshot AccessSnapshot
	if json.Unmarshal(encoded, &snapshot) != nil {
		return AccessSnapshot{}, ErrUnavailable
	}
	snapshot, err := s.accessSnapshot(snapshot)
	if err != nil {
		return AccessSnapshot{}, ErrUnavailable
	}
	return snapshot, nil
}

func (s *Store) Access(ctx context.Context) (AccessSnapshot, uint64, error) {
	conn, err := s.connection(ctx)
	if err != nil {
		return AccessSnapshot{}, 0, err
	}
	defer conn.Close()
	revision, err := s.metadata(ctx, conn)
	if err != nil {
		return AccessSnapshot{}, 0, err
	}
	snapshot, err := s.readAccess(ctx, conn)
	if err != nil {
		return AccessSnapshot{}, 0, err
	}
	if err := s.checkFiles(); err != nil {
		return AccessSnapshot{}, 0, err
	}
	return snapshot, revision, nil
}

// AuthorizeAccess checks only the stored access rule on the original public URI.
// It does not establish caller identity, JWT validity or route ownership.
func (s *Store) AuthorizeAccess(ctx context.Context, caller, target, method, rawURI string, hasUser bool) (uint64, error) {
	path, err := v1.DecodeRoutePath(rawURI)
	if err != nil || !identifier(caller, 64) || !identifier(target, 64) {
		return 0, ErrDenied
	}
	snapshot, revision, err := s.Access(ctx)
	if err != nil {
		return 0, err
	}
	for _, rule := range snapshot.InternalOnly {
		if rule.Target == target && slices.Contains(rule.Methods, method) && matchesAny(rule.Paths, path) && !slices.Contains(rule.Callers, caller) {
			return 0, ErrDenied
		}
	}
	for _, rule := range snapshot.Policies {
		if rule.Caller == caller && rule.Target == target && slices.Contains(rule.Methods, method) && matchesAny(rule.Paths, path) && ((hasUser && rule.AllowUserContext) || (!hasUser && rule.AllowBackground)) {
			return revision, nil
		}
	}
	return 0, ErrDenied
}
func matchesAny(prefixes []string, path string) bool {
	for _, prefix := range prefixes {
		if v1.MatchesPrefix(prefix, path) {
			return true
		}
	}
	return false
}
