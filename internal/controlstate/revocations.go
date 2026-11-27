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

// Revoke requires current security-admin authorization checked by its caller,
// including for retries. Actor comes from authenticated state, never the body.
func (s *Store) Revoke(ctx context.Context, c Command) (Result, error) {
	now := time.Now().UTC()
	if !c.valid(now) {
		return Result{}, ErrConfig
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return Result{}, ErrConfig
	}
	fingerprint := sha256.Sum256(encoded)
	conn, err := s.connection(ctx)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer tx.Rollback()
	revision, err := s.metadata(ctx, tx)
	if err != nil {
		return Result{}, err
	}
	var previous []byte
	var previousRevision, previousTime string
	err = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(fingerprint)=32 THEN fingerprint ELSE NULL END,CASE WHEN length(revision)<=20 THEN revision ELSE NULL END,CASE WHEN length(revoked_at)<=35 THEN revoked_at ELSE NULL END FROM control_operations WHERE id=?", c.OperationID).Scan(&previous, &previousRevision, &previousTime)
	switch {
	case err == nil:
		if len(previous) != len(fingerprint) {
			return Result{}, ErrUnavailable
		}
		if string(previous) != string(fingerprint[:]) {
			return Result{}, ErrConflict
		}
		result, err := decodeResult(c.Target, previousRevision, previousTime)
		if err != nil {
			return Result{}, err
		}
		if err := s.checkFiles(); err != nil {
			return Result{}, err
		}
		return result, nil
	case !errors.Is(err, sql.ErrNoRows):
		return Result{}, ErrUnavailable
	}
	if c.ExpectedRevision != revision {
		return Result{}, ErrConflict
	}
	if revision == math.MaxUint64 {
		return Result{}, ErrUnavailable
	}
	var found int
	err = tx.QueryRowContext(ctx, "SELECT 1 FROM credential_revocations WHERE kind=? AND service_id=? AND value=?", c.Target.Kind, c.Target.ServiceID, c.Target.Value).Scan(&found)
	if err == nil {
		return Result{}, ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Result{}, ErrUnavailable
	}
	next := strconv.FormatUint(revision+1, 10)
	timestamp := now.Format(time.RFC3339Nano)
	payload, err := json.Marshal(Event{OperationID: c.OperationID, Actor: c.Actor, Revision: next, Target: c.Target, Reason: c.Reason, RevokedAt: now})
	if err != nil || len(payload) > 4096 {
		return Result{}, ErrConfig
	}
	var count int
	var bytes int64
	if tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(payload)),0) FROM control_outbox").Scan(&count, &bytes) != nil {
		return Result{}, ErrUnavailable
	}
	if count >= s.config.MaxOutboxEvents || bytes > s.config.MaxOutboxBytes-int64(len(payload)) {
		return Result{}, ErrOutboxFull
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO credential_revocations VALUES(?,?,?,?,?)", c.Target.Kind, c.Target.ServiceID, c.Target.Value, next, timestamp); err != nil {
		return Result{}, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO control_operations VALUES(?,?,?,?)", c.OperationID, fingerprint[:], next, timestamp); err != nil {
		return Result{}, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO control_outbox VALUES(?,?,?)", c.OperationID, next, payload); err != nil {
		return Result{}, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "UPDATE control_metadata SET revision=? WHERE id=1", next); err != nil {
		return Result{}, ErrUnavailable
	}
	if err := s.checkFiles(); err != nil {
		return Result{}, err
	}
	if err := tx.Commit(); err != nil {
		return Result{}, ErrUnavailable
	}
	if err := s.checkFiles(); err != nil {
		return Result{}, err
	}
	return Result{Target: c.Target, Revision: revision + 1, RevokedAt: now}, nil
}

func decodeResult(target Target, revision, timestamp string) (Result, error) {
	number, err := strconv.ParseUint(revision, 10, 64)
	when, timeErr := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != revision || timeErr != nil {
		return Result{}, ErrUnavailable
	}
	return Result{Target: target, Revision: number, RevokedAt: when}, nil
}

// IsRevoked applies service-wide revocation to every credential of that service.
// Errors must deny admission. Active-flow termination needs runtime integration.
func (s *Store) IsRevoked(ctx context.Context, target Target) (bool, error) {
	if !target.valid() {
		return false, ErrConfig
	}
	conn, err := s.connection(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err := s.metadata(ctx, conn); err != nil {
		return false, err
	}
	var found int
	err = conn.QueryRowContext(ctx, `SELECT 1 FROM credential_revocations WHERE service_id=? AND ((kind=? AND value=?) OR kind='service') LIMIT 1`, target.ServiceID, target.Kind, target.Value).Scan(&found)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, ErrUnavailable
	}
	if fileErr := s.checkFiles(); fileErr != nil {
		return false, fileErr
	}
	return err == nil, nil
}

// Events returns up to 200 committed events in revision order, for at-least-once
// export. The publisher acknowledges only after a durable external ack.
func (s *Store) Events(ctx context.Context, after uint64, limit int) ([]Event, error) {
	if limit < 1 || limit > 200 {
		return nil, ErrConfig
	}
	conn, err := s.connection(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := s.metadata(ctx, conn); err != nil {
		return nil, err
	}
	cursor := strconv.FormatUint(after, 10)
	rows, err := conn.QueryContext(ctx, `SELECT CASE WHEN length(id)=36 THEN id ELSE NULL END,CASE WHEN length(revision)<=20 THEN revision ELSE NULL END,CASE WHEN length(payload)<=4096 THEN payload ELSE NULL END FROM control_outbox WHERE length(revision)>? OR (length(revision)=? AND revision>?) ORDER BY length(revision),revision LIMIT ?`, len(cursor), len(cursor), cursor, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := make([]Event, 0, limit)
	for rows.Next() {
		var id, revision string
		var payload []byte
		if rows.Scan(&id, &revision, &payload) != nil || len(payload) == 0 {
			return nil, ErrUnavailable
		}
		var event Event
		if json.Unmarshal(payload, &event) != nil || event.OperationID != id || event.Revision != revision || !event.Target.valid() || event.RevokedAt.IsZero() {
			return nil, ErrUnavailable
		}
		if _, err := decodeResult(event.Target, event.Revision, event.RevokedAt.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	if err := s.checkFiles(); err != nil {
		return nil, err
	}
	return result, nil
}

// Acknowledge removes the delivered event, retaining the operation result and
// revocation. It is idempotent and does not change the control revision.
func (s *Store) Acknowledge(ctx context.Context, operationID string) error {
	if !clean(operationID, 36) {
		return ErrConfig
	}
	conn, err := s.connection(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	if _, err := s.metadata(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM control_outbox WHERE id=?", operationID); err != nil {
		return ErrUnavailable
	}
	if err := s.checkFiles(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return s.checkFiles()
}
