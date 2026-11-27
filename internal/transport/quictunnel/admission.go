package quictunnel

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/peeridentity"
	"github.com/solodyagin/outgate/internal/registry"
)

type RegistrationGuard struct {
	Store       *controlstate.Store
	TrustDomain string
	// Before enforces registration rate limits and runtime readiness before
	// credential hashing/storage work. Required; no permissive default is supplied.
	Before func(context.Context, tls.ConnectionState) error
	// Commit owns registry conflict/permission checks and required durable route
	// commit/outbox/resync. Return a fresh unready session and a validated ack.
	// It may retain the lease for later bounded security freshness checks.
	Commit func(context.Context, tls.ConnectionState, v1.Register, *controlstate.RegistrationLease) (Binding, error)
}

// GuardRegistration adds verified TLS identity, durable credential-generation
// fencing and one-live-owner protection around the registry admission callback.
// It never fabricates SecurityReady or substitutes a RAM registry commit.
func GuardRegistration(config RegistrationGuard) (Admit, error) {
	if config.Store == nil || !peeridentity.ValidTrustDomain(config.TrustDomain) || config.Before == nil || config.Commit == nil {
		return nil, controlstate.ErrConfig
	}
	return func(ctx context.Context, state tls.ConnectionState, credential []byte, reg v1.Register) (out Binding, failure error) {
		defer func() {
			if failure != nil {
				failure = registrationRejection(failure)
			}
		}()
		if err := config.Before(ctx, state); err != nil {
			return Binding{}, err
		}
		peer, ok := peeridentity.Read(&state, config.TrustDomain, time.Now())
		if !ok || peer.Certificate.SerialNumber == nil {
			return Binding{}, controlstate.ErrDenied
		}
		if len(credential) == 0 || len(credential) > 385 {
			return Binding{}, controlstate.ErrDenied
		}
		identity := controlstate.GrantPeer{ServiceID: peer.ServiceID, InstanceID: peer.InstanceID, SPKI: hex.EncodeToString(peer.SPKI[:]), CertificateSerial: peer.Certificate.SerialNumber.Text(16)}
		lease, err := config.Store.AcquireRegistration(ctx, string(credential), identity, reg)
		if err != nil {
			return Binding{}, err
		}
		expiry := lease.Grant.ExpiresAt
		if peer.Certificate.NotAfter.Before(expiry) {
			expiry = peer.Certificate.NotAfter
		}
		binding, err := config.Commit(ctx, state, reg, lease)
		prior := binding.Release
		var once sync.Once
		binding.Release = func() {
			once.Do(func() {
				defer lease.Release()
				if prior != nil {
					prior()
				}
			})
		}
		if err != nil {
			return binding, err
		}
		// The transport still validates the entire ack and exact original register.
		// Credential expiry is separate from the short renewable security lease.
		stamp := expiry.Unix()
		binding.Ack.CredentialExpiresAt = &stamp
		if reg.CredentialGeneration != nil {
			generation := *reg.CredentialGeneration
			binding.Ack.CredentialGeneration = &generation
		}
		deadline := time.Now().Add(5 * time.Second)
		if expiry.Before(deadline) {
			deadline = expiry
		}
		if binding.SecurityDeadline.IsZero() || deadline.Before(binding.SecurityDeadline) {
			binding.SecurityDeadline = deadline
		}
		if _, err := lease.Check(ctx); err != nil {
			return binding, err
		}
		return binding, nil
	}, nil
}

// Permanent credential errors must not become retryable storage failures.
func registrationRejection(err error) error {
	code := ""
	retry := false
	switch {
	case errors.Is(err, controlstate.ErrDenied):
		code = "auth_failed"
	case errors.Is(err, controlstate.ErrInstanceInUse), errors.Is(err, registry.ErrDuplicate):
		code = "duplicate_instance"
		retry = true
	case errors.Is(err, controlstate.ErrRegistrationQuota), errors.Is(err, registry.ErrQuota):
		code = "quota_exceeded"
		retry = true
	case errors.Is(err, registry.ErrInvalid):
		code = "invalid_register"
	case errors.Is(err, registry.ErrPathForbidden), errors.Is(err, registry.ErrUnknownService):
		code = "path_forbidden"
	case errors.Is(err, registry.ErrPathConflict):
		code = "path_conflict"
	default:
		return err // bootstrap safely maps opaque failures to state_unavailable
	}
	return &quiccontrol.Rejection{Nack: v1.RegisterNack{Type: "register_nack", Code: code, Retryable: retry, Detail: "registration refused"}}
}
