package quictunnel

import (
	"context"
	"time"

	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/controlstate"
)

// SQLiteAdmissionSecurity binds actual control/replay health to admission and
// renewal. A healthy replay warmup returns its original barrier, not an error or
// permission to bypass Ready/Reserve. Per-lease revocation/generation/identity
// checks remain in DurableAdmission; other runtime dependencies may compose this
// callback with their own checks. Stores must already be explicitly provisioned.
func SQLiteAdmissionSecurity(control *controlstate.Store, replayStore *replay.SQLite) (func(context.Context) (AdmissionSecurity, error), error) {
	if control == nil || replayStore == nil {
		return nil, controlstate.ErrConfig
	}
	return func(ctx context.Context) (AdmissionSecurity, error) {
		started := time.Now()
		if _, err := control.Revision(ctx); err != nil {
			return AdmissionSecurity{}, err
		}
		barrier, err := replayStore.Health(ctx)
		if err != nil {
			return AdmissionSecurity{}, err
		}
		deadline := started.Add(5 * time.Second)
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return AdmissionSecurity{}, controlstate.ErrUnavailable
		}
		return AdmissionSecurity{ValidUntil: deadline, ReadyNotBefore: barrier}, nil
	}, nil
}
