package quictunnel

import (
	"time"

	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
)

// armExpiry runs under the session mutex, before registry operations. Its timer
// closes native I/O independently of that mutex: a registry publication may
// legitimately hold its own lock throughout a bounded SQL commit.
func (s *BoundSession) armExpiry(deadline time.Time, renewable bool) error {
	s.expiryMu.Lock()
	defer s.expiryMu.Unlock()
	if s.expiryFired {
		return sessionstate.ErrSecurity
	}
	if renewable {
		s.expiryLease = deadline
	} else {
		s.expiryHard = earlierDeadline(s.expiryHard, deadline)
	}
	deadline = earlierDeadline(s.expiryHard, s.expiryLease)
	if deadline.IsZero() || deadline.Equal(s.expiryDeadline) {
		return nil
	}
	s.expiryDeadline = deadline
	delay := max(time.Nanosecond, time.Until(deadline))
	if s.expiryTimer == nil {
		s.expiryTimer = time.AfterFunc(delay, s.expireNative)
	} else {
		s.expiryTimer.Reset(delay)
	}
	return nil
}

func (s *BoundSession) expireNative() {
	s.expiryMu.Lock()
	if s.expiryFired {
		s.expiryMu.Unlock()
		return
	}
	if remaining := time.Until(s.expiryDeadline); remaining > 0 {
		s.expiryTimer.Reset(remaining)
		s.expiryMu.Unlock()
		return
	}
	s.expiryFired = true
	s.expiryMu.Unlock()
	// No session or registry lock is needed to interrupt native streams.
	_ = s.conn.CloseWithError(quiccontrol.CodeCredentialRevoked, "credential_revoked")
	s.cancel()
	s.Revoke()
}

func (s *BoundSession) stopExpiry() {
	s.expiryMu.Lock()
	defer s.expiryMu.Unlock()
	s.expiryFired = true
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
	}
}

func earlierDeadline(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}
