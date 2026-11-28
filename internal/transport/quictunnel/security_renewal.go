package quictunnel

import (
	"context"
	"time"

	"github.com/solodyagin/outgate-sdk/sessionstate"
)

// SecurityLease is a fresh external authorization assertion, not readiness proof
// from an instance_status. Deadline must be nonzero, future and at most 5s away.
type SecurityLease struct {
	Ready    bool
	Deadline time.Time
}

// SecurityRenewal bounds each live session to one cooperative checker. Zero
// settings select one-second interval/timeout; nonzero settings may tighten them.
// Cleanup retains ownership until an outstanding checker has actually returned.
type SecurityRenewal struct {
	Interval time.Duration
	Timeout  time.Duration
}

func (o SecurityRenewal) normalized() (SecurityRenewal, error) {
	if o.Interval == 0 {
		o.Interval = time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = time.Second
	}
	if o.Interval <= 0 || o.Interval > time.Second || o.Timeout <= 0 || o.Timeout > time.Second {
		return o, sessionstate.ErrProtocol
	}
	return o, nil
}

// RenewSecurity replaces only the renewable security freshness lease. Legacy
// SetSecurity deadlines, credential expiry, replay/status gates and drain intent
// remain hard bounds. Terminal/expired sessions cannot be revived.
func (s *BoundSession) RenewSecurity(ready bool, deadline time.Time) error {
	s.mu.Lock()
	if s.closing || !s.model.Snapshot().TransportActive {
		s.mu.Unlock()
		return sessionstate.ErrState
	}
	effect, err := s.model.RenewSecurity(ready, deadline, time.Now())
	if err == nil {
		err = s.armExpiry(deadline, true)
	}
	if err == nil {
		err = s.syncReadyLocked()
	}
	s.mu.Unlock()
	s.signalTimer()
	if err != nil || effect.CloseTransport {
		s.stop(err)
	}
	return err
}

func (s *BoundSession) signalTimer() {
	select {
	case s.timerWake <- struct{}{}:
	default:
	}
}

func (s *BoundSession) renewalLoop(check func(context.Context) (SecurityLease, error), options SecurityRenewal, deadline time.Time) {
	defer close(s.renewalDone)
	if check == nil {
		return
	}
	timer := time.NewTimer(time.Nanosecond)
	defer timer.Stop()
	for {
		s.mu.Lock()
		active := !s.closing && s.model.Snapshot().TransportActive
		s.mu.Unlock()
		if !active {
			return
		}
		// Short leases are checked earlier rather than waiting for a fixed period.
		remaining := time.Until(deadline)
		if remaining <= 0 {
			s.Revoke()
			return
		}
		timer.Reset(min(options.Interval, max(time.Nanosecond, remaining/2)))
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
		}
		ctx, cancel := context.WithTimeout(s.ctx, min(options.Timeout, max(time.Nanosecond, time.Until(deadline))))
		lease, err := check(ctx)
		expired := ctx.Err() != nil
		cancel()
		if err != nil || expired {
			if s.ctx.Err() == nil {
				s.Revoke()
			}
			return
		}
		if err := s.RenewSecurity(lease.Ready, lease.Deadline); err != nil {
			return
		}
		deadline = lease.Deadline
	}
}
