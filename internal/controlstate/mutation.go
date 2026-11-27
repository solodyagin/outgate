package controlstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"
)

// securityMutation uses the same revision/operation/outbox transaction as revoke.
// Only sanitized results enter security_results; its callback must never return
// a credential or secret digest in the result or event target.
func (s *Store) securityMutation(ctx context.Context, c Change, action string, request any, apply func(*sql.Tx, uint64, time.Time) ([]byte, Target, error)) ([]byte, bool, error) {
	now := time.Now().UTC()
	if !c.valid(now) {
		return nil, false, ErrConfig
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > maxSecurityDocument {
		return nil, false, ErrConfig
	}
	fingerprint := sha256.Sum256(encoded)
	conn, err := s.connection(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, ErrUnavailable
	}
	defer tx.Rollback()
	revision, err := s.metadata(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	var previous []byte
	var previousAction sql.NullString
	var result []byte
	err = tx.QueryRowContext(ctx, `SELECT CASE WHEN length(o.fingerprint)=32 THEN o.fingerprint ELSE NULL END,CASE WHEN length(r.action)<=32 THEN r.action ELSE NULL END,CASE WHEN length(r.result)<=1048576 THEN r.result ELSE NULL END FROM control_operations o LEFT JOIN security_results r ON r.id=o.id WHERE o.id=?`, c.OperationID).Scan(&previous, &previousAction, &result)
	if err == nil {
		if !previousAction.Valid || previousAction.String != action || string(previous) != string(fingerprint[:]) {
			return nil, false, ErrConflict
		}
		if len(result) == 0 {
			return nil, false, ErrUnavailable
		}
		if err := s.checkFiles(); err != nil {
			return nil, false, err
		}
		return result, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrUnavailable
	}
	if c.ExpectedRevision != revision {
		return nil, false, ErrConflict
	}
	if revision == math.MaxUint64 {
		return nil, false, ErrUnavailable
	}
	result, target, err := apply(tx, revision+1, now)
	if err != nil {
		return nil, false, err
	}
	if len(result) == 0 || len(result) > maxSecurityDocument {
		return nil, false, ErrConfig
	}
	next := strconv.FormatUint(revision+1, 10)
	event, err := json.Marshal(Event{OperationID: c.OperationID, Actor: c.Actor, Revision: next, Target: target, Reason: c.Reason, Action: action, OccurredAt: now, ObjectDigest: fmtDigest(fingerprint)})
	if err != nil || len(event) > 4096 {
		return nil, false, ErrConfig
	}
	var count int
	var bytes int64
	if tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(payload)),0) FROM control_outbox").Scan(&count, &bytes) != nil {
		return nil, false, ErrUnavailable
	}
	if count >= s.config.MaxOutboxEvents || bytes > s.config.MaxOutboxBytes-int64(len(event)) {
		return nil, false, ErrOutboxFull
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO control_operations VALUES(?,?,?,?)", c.OperationID, fingerprint[:], next, now.Format(time.RFC3339Nano)); err != nil {
		return nil, false, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO security_results VALUES(?,?,?)", c.OperationID, action, result); err != nil {
		return nil, false, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO control_outbox VALUES(?,?,?)", c.OperationID, next, event); err != nil {
		return nil, false, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "UPDATE control_metadata SET revision=? WHERE id=1", next); err != nil {
		return nil, false, ErrUnavailable
	}
	if err := s.checkFiles(); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, ErrUnavailable
	}
	if err := s.checkFiles(); err != nil {
		return nil, false, err
	}
	return result, true, nil
}
