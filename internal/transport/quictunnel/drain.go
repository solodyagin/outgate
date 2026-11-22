package quictunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
)

type nativeControl struct {
	kind string
	id   v1.U64
}

func (s *BoundSession) signalWriter() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *BoundSession) pauseLocked() {
	if !s.paused {
		s.watermark = s.raw.requests.Pause()
		s.paused = true
	}
	_ = s.routes.Drain(s.handle)
}
func (s *BoundSession) enqueueLocked(kind string, id v1.U64) error {
	if len(s.pending) >= s.maxCommands {
		return sessionstate.ErrCapacity
	}
	s.pending = append(s.pending, nativeControl{kind: kind, id: id})
	return nil
}

// Drain stops new assignments immediately, waits for both directions of all
// admitted exchanges, then sends a negotiated quiescent drain. Normal completion
// requires service drain_ack, unregister, actual exclusion and unregister_ack.
// Security/deadlines can preempt it. Close remains immediate cancellation.
func (s *BoundSession) Drain(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	id := binary.BigEndian.Uint64(b[:])
	if id == 0 {
		id = 1
	}
	s.mu.Lock()
	if !s.fenceCap {
		s.mu.Unlock()
		return ErrControlNotIntegrated
	}
	if s.closing {
		s.mu.Unlock()
		return s.waitDrain(ctx)
	}
	deadline, _ := ctx.Deadline()
	effect, err := s.model.Close(deadline, time.Now())
	if err == nil && !s.localDrain && !s.peerDrain {
		s.localDrain = true
		err = s.enqueueLocked("drain", v1.U64(id))
	}
	s.localDrain = true
	if err == nil {
		s.pauseLocked()
		err = s.syncReadyLocked()
	}
	s.mu.Unlock()
	if err != nil || effect.CloseTransport {
		s.stop(err)
	} else {
		s.signalWriter()
	}
	return s.waitDrain(ctx)
}
func (s *BoundSession) waitDrain(ctx context.Context) error {
	select {
	case <-s.done:
		s.mu.Lock()
		err, graceful := s.cause, s.graceful
		s.mu.Unlock()
		if graceful {
			return nil
		}
		return err
	case <-ctx.Done():
		s.stop(ctx.Err())
		return ctx.Err()
	}
}

func (s *BoundSession) receiveLocked(message any) (sessionstate.Effect, error, bool) {
	if _, ok := message.(v1.InstanceStatus); ok {
		e, err := s.model.Apply(sessionstate.Service, message, time.Now())
		return e, err, false
	}
	if !s.fenceCap {
		return sessionstate.Effect{}, ErrControlNotIntegrated, false
	}
	switch m := message.(type) {
	case v1.Drain:
		e, err := s.model.Apply(sessionstate.Service, m, time.Now())
		if err == nil {
			s.peerDrain = true
			if !s.localDrainSent {
				// Join a peer drain if our local intent has not gone on the wire.
				// Already transmitted commands still require their own acknowledgments.
				for i := 0; i < len(s.pending); i++ {
					if s.pending[i].kind == "drain" {
						copy(s.pending[i:], s.pending[i+1:])
						s.pending[len(s.pending)-1] = nativeControl{}
						s.pending = s.pending[:len(s.pending)-1]
						break
					}
				}
			}
			s.pauseLocked()
			err = s.enqueueLocked("drain_ack", m.CommandID)
		}
		return e, err, false
	case v1.DrainAck:
		e, err := s.model.Apply(sessionstate.Service, m, time.Now())
		return e, err, false
	case v1.Unregister:
		if !s.peerDrain && !s.localDrainSent {
			return sessionstate.Effect{}, v1.ErrProtocol, false
		}
		e, err := s.model.Apply(sessionstate.Service, m, time.Now())
		if err != nil {
			return e, err, false
		}
		// Exclude from dispatch, but retain the instance/quota reservation until
		// the carrier closes. Otherwise a peer withholding normal close could
		// accumulate terminal-ack connections outside the registry tunnel limit.
		if err = s.routes.Drain(s.handle); err != nil {
			return e, err, false
		}
		if err = s.routes.SetReady(s.handle, false); err != nil {
			return e, err, false
		}
		s.excluded = true
		e, err = s.model.ConfirmExcluded(time.Now())
		if err == nil {
			err = s.enqueueLocked("unregister_ack", m.CommandID)
		}
		return e, err, err == nil
	default:
		return sessionstate.Effect{}, v1.ErrProtocol, false
	}
}

func (s *BoundSession) writerLoop() {
	defer close(s.writerDone)
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
			for {
				s.mu.Lock()
				if s.closing || s.model.Snapshot().NativeActive != 0 || len(s.pending) == 0 {
					s.mu.Unlock()
					break
				}
				item := s.pending[0]
				copy(s.pending, s.pending[1:])
				s.pending[len(s.pending)-1] = nativeControl{}
				s.pending = s.pending[:len(s.pending)-1]
				snapshot := s.model.Snapshot()
				deadline := snapshot.Deadline
				var message any
				switch item.kind {
				case "drain":
					ms := min(int(time.Until(deadline)/time.Millisecond), 30000)
					if ms < 1 {
						s.mu.Unlock()
						s.stop(sessionstate.ErrTimeout)
						return
					}
					message = v1.Drain{Type: "drain", CommandID: item.id, DeadlineMS: ms, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(s.watermark)}
				case "drain_ack":
					message = v1.DrainAck{Type: "drain_ack", CommandID: item.id, Extensions: v1.QUICQuiescentFenceExtensions(s.watermark)}
				case "unregister_ack":
					message = v1.UnregisterAck{Type: "unregister_ack", CommandID: item.id}
					s.terminalWrite = true
				}
				effect, err := s.model.Apply(sessionstate.Gateway, message, time.Now())
				if err == nil && item.kind == "drain" {
					s.localDrainSent = true
				}
				s.mu.Unlock()
				if err != nil {
					s.stop(err)
					return
				}
				ctx, cancel := context.WithDeadline(s.ctx, deadline)
				err = s.raw.Send(ctx, message)
				cancel()
				if err != nil {
					s.stop(err)
					return
				}
				if effect.CloseTransport {
					// Keep the carrier alive so the peer can consume unregister_ack.
					// A valid service closes normally after applying that ack.
					ctx, cancel := context.WithDeadline(s.ctx, deadline)
					select {
					case <-s.conn.Context().Done():
						cause := context.Cause(s.conn.Context())
						var application *quic.ApplicationError
						if errors.As(cause, &application) && application.ErrorCode == quiccontrol.CodeNormal {
							s.mu.Lock()
							s.graceful = true
							s.mu.Unlock()
							s.stop(context.Canceled)
						} else {
							s.stop(cause)
						}
					case <-ctx.Done():
						s.stop(ctx.Err())
					}
					cancel()
					return
				}
			}
		}
	}
}
