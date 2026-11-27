package servicecall

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/solodyagin/outgate-sdk/delegation"
	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
)

type AcceptedKey struct {
	Key      delivery.Key
	NotAfter time.Time // required accepted-key lifetime, never an unbounded default
}

type CallerLimit struct{ PerSecond, Burst int }

type StateConfig struct {
	Store *controlstate.Store
	// Keys supplies currently accepted HMAC keys, bound to the exact leg/service.
	// Hints never select another service. The source must honor cancellation and
	// rotation; its secrets are copied before use. JWT keys are a separate source.
	Keys    func(context.Context, string, string, string) (AcceptedKey, error)
	Callers map[string]CallerLimit
	// CheckUser is required for verified user calls. It checks authoritative
	// issuer/session/jti revocation freshness and returns its security deadline.
	// Nil permits background calls only, even if a JWT verifier is configured.
	CheckUser func(context.Context, delegation.Identity) (time.Time, error)
}

type callerBucket struct {
	limit  CallerLimit
	tokens float64
	last   time.Time
}
type stateAdmission struct {
	config  StateConfig
	mu      sync.Mutex
	callers map[string]*callerBucket
}

// BindStateAdmission installs the durable caller/policy/revocation boundary and
// post-commit recheck. Resolve must still supply the authenticated live recipient
// transport; its TLS/grant/session freshness is enforced by that transport's
// lifecycle. This does not implement registration admission or the launcher.
// Mixed custom Authenticate/Authorize/Revalidate callbacks are rejected.
func BindStateAdmission(config Config, state StateConfig) (Config, error) {
	if state.Store == nil || state.Keys == nil || len(state.Callers) == 0 || len(state.Callers) > 256 || config.Authenticate != nil || config.Authorize != nil || config.Revalidate != nil || config.Resolve == nil {
		return Config{}, ErrConfig
	}
	admission := &stateAdmission{config: state, callers: make(map[string]*callerBucket, len(state.Callers))}
	now := time.Now()
	for id, limit := range state.Callers {
		if !validID(id, 64) || limit.PerSecond < 1 || limit.PerSecond > 1000000 || limit.Burst < 1 || limit.Burst > 1000000 {
			return Config{}, ErrConfig
		}
		admission.callers[id] = &callerBucket{limit: limit, tokens: float64(limit.Burst), last: now}
	}
	admission.config.Callers = nil // retain only the private fixed-size bucket map
	resolve := config.Resolve
	config.Authenticate = admission.authenticate
	config.Authorize = admission.authorize
	config.Revalidate = admission.revalidate
	config.Resolve = func(ctx context.Context, route registry.Decision) (Recipient, error) {
		recipient, err := resolve(ctx, route)
		if err != nil {
			return Recipient{}, err
		}
		accepted, err := admission.recipientKey(ctx, route, recipient)
		if err != nil {
			return Recipient{}, err
		}
		recipient.Key = accepted.Key
		if recipient.ValidUntil.IsZero() || accepted.NotAfter.Before(recipient.ValidUntil) {
			recipient.ValidUntil = accepted.NotAfter
		}
		return recipient, nil
	}
	return config, nil
}

func (a *stateAdmission) take(caller string, now time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	bucket := a.callers[caller]
	if bucket == nil {
		return delivery.ErrDelivery
	}
	if elapsed := now.Sub(bucket.last); elapsed > 0 {
		bucket.tokens = min(float64(bucket.limit.Burst), bucket.tokens+elapsed.Seconds()*float64(bucket.limit.PerSecond))
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return ErrRateLimited
	}
	bucket.tokens--
	return nil
}

func statePeer(peer Peer) (controlstate.GrantPeer, error) {
	if peer.Certificate == nil || peer.Certificate.SerialNumber == nil || sha256.Sum256(peer.Certificate.RawSubjectPublicKeyInfo) != peer.SPKI {
		return controlstate.GrantPeer{}, delivery.ErrDelivery
	}
	return controlstate.GrantPeer{ServiceID: peer.ServiceID, InstanceID: peer.InstanceID, SPKI: hex.EncodeToString(peer.SPKI[:]), CertificateSerial: peer.Certificate.SerialNumber.Text(16)}, nil
}

func (a *stateAdmission) key(ctx context.Context, leg, service, id string) (AcceptedKey, error) {
	if !validID(id, 128) {
		return AcceptedKey{}, controlstate.ErrDenied
	}
	revoked, err := a.config.Store.IsRevoked(ctx, controlstate.Target{Kind: "hmac_key_id", ServiceID: service, Value: id})
	if err != nil {
		return AcceptedKey{}, err
	}
	if revoked {
		return AcceptedKey{}, controlstate.ErrDenied
	}
	accepted, err := a.config.Keys(ctx, leg, service, id)
	if err != nil {
		return AcceptedKey{}, err
	}
	if accepted.Key.ID != id || len(accepted.Key.Secret) < 32 || len(accepted.Key.Secret) > 4096 || !time.Now().Before(accepted.NotAfter) {
		return AcceptedKey{}, controlstate.ErrDenied
	}
	accepted.Key.Secret = slices.Clone(accepted.Key.Secret)
	return accepted, nil
}

func callerError(err error) error {
	if errors.Is(err, controlstate.ErrDenied) {
		return delivery.ErrDelivery
	}
	return err
}

func (a *stateAdmission) credentials(ctx context.Context, peer Peer, grant, id string) (controlstate.GrantRecord, AcceptedKey, error) {
	identity, err := statePeer(peer)
	if err != nil {
		return controlstate.GrantRecord{}, AcceptedKey{}, err
	}
	record, err := a.config.Store.GrantForPeer(ctx, grant, identity)
	if err != nil {
		return controlstate.GrantRecord{}, AcceptedKey{}, callerError(err)
	}
	accepted, err := a.key(ctx, httpsig.Call, peer.ServiceID, id)
	if err != nil {
		return controlstate.GrantRecord{}, AcceptedKey{}, callerError(err)
	}
	return record, accepted, nil
}

func (a *stateAdmission) authenticate(ctx context.Context, peer Peer, grant, id string) (delivery.Key, error) {
	if err := ctx.Err(); err != nil {
		return delivery.Key{}, err
	}
	if err := a.take(peer.ServiceID, time.Now()); err != nil {
		return delivery.Key{}, err
	}
	_, accepted, err := a.credentials(ctx, peer, grant, id)
	if err != nil {
		return delivery.Key{}, err
	}
	return accepted.Key, nil
}

func (a *stateAdmission) authorize(ctx context.Context, call Call) (time.Time, error) {
	path, err := v1.DecodeRoutePath(call.RawURI)
	if err != nil || path != call.Path {
		return time.Time{}, ErrForbidden
	}
	grant, key, err := a.credentials(ctx, call.Peer, call.GrantID, call.KeyID)
	if err != nil {
		return time.Time{}, err
	}
	if _, err := a.config.Store.AuthorizeAccess(ctx, call.Peer.ServiceID, call.Target, call.Method, call.RawURI, call.HasUser); err != nil {
		if errors.Is(err, controlstate.ErrDenied) {
			return time.Time{}, ErrForbidden
		}
		return time.Time{}, err
	}
	until := earliest(time.Now().Add(5*time.Second), grant.ExpiresAt, key.NotAfter)
	if call.HasUser {
		if a.config.CheckUser == nil {
			return time.Time{}, ErrForbidden
		}
		userUntil, err := a.config.CheckUser(ctx, call.User)
		if err != nil {
			if errors.Is(err, controlstate.ErrDenied) {
				return time.Time{}, ErrForbidden
			}
			return time.Time{}, err
		}
		if !time.Now().Before(userUntil) {
			return time.Time{}, controlstate.ErrUnavailable
		}
		until = earliest(until, userUntil, call.User.ExpiresAt)
	}
	return until, nil
}

func (a *stateAdmission) recipientKey(ctx context.Context, route registry.Decision, recipient Recipient) (AcceptedKey, error) {
	if route.Session == nil || recipient.Transport == nil || recipient.Transport.Handle() != route.Session || route.ServiceID != route.Session.Instance().ServiceID {
		return AcceptedKey{}, controlstate.ErrUnavailable
	}
	accepted, err := a.key(ctx, httpsig.Gateway, route.ServiceID, recipient.Key.ID)
	if err != nil {
		return AcceptedKey{}, controlstate.ErrUnavailable
	}
	if subtle.ConstantTimeCompare(accepted.Key.Secret, recipient.Key.Secret) != 1 {
		return AcceptedKey{}, controlstate.ErrUnavailable
	}
	return accepted, nil
}

func (a *stateAdmission) revalidate(ctx context.Context, call Call, original delivery.Key, route registry.Decision, recipient Recipient) error {
	until, err := a.authorize(ctx, call)
	if err != nil {
		return err
	}
	_, current, err := a.credentials(ctx, call.Peer, call.GrantID, original.ID)
	if err != nil {
		return err
	}
	if current.Key.ID != original.ID || subtle.ConstantTimeCompare(current.Key.Secret, original.Secret) != 1 {
		return delivery.ErrDelivery
	}
	accepted, err := a.recipientKey(ctx, route, recipient)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); !ok || deadline.After(earliest(until, current.NotAfter, accepted.NotAfter)) {
		return controlstate.ErrUnavailable
	}
	return ctx.Err()
}

func earliest(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}
