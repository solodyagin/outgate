package quictunnel

import (
	"context"
	"crypto/tls"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/peeridentity"
	"github.com/solodyagin/outgate/internal/registry"
)

// AdmissionSecurity is a verified local assertion that mandatory control,
// revocation and replay sources are healthy. ValidUntil must be future and no
// more than five seconds away. A healthy replay warmup uses a future
// ReadyNotBefore, permitting registered-but-unready sessions. Missing/unhealthy
// sources return an error instead. This callback must honor its bounded context.
type AdmissionSecurity struct {
	ValidUntil     time.Time
	ReadyNotBefore time.Time
}

type DurableAdmissionConfig struct {
	Owner       *controlstate.RegistrationOwner
	TrustDomain string
	Limits      RegistrationLimits
	Policy      RegistrationPolicy
	Bound       BoundOptions
	Renewal     SecurityRenewal
	Security    func(context.Context) (AdmissionSecurity, error)
}

// DurableAdmission joins bounded registration gates, verified identity/grants,
// SQLite publication, negotiated ack and exact native cleanup. It does not own
// listener/TLS socket budgets or administrative activation.
type DurableAdmission struct {
	config     DurableAdmissionConfig
	gate       *registrationGate
	renewSlots chan struct{}
}

func NewDurableAdmission(config DurableAdmissionConfig) (*DurableAdmission, error) {
	if config.Owner == nil || !peeridentity.ValidTrustDomain(config.TrustDomain) || config.Security == nil || config.Policy.validate() != nil || config.Bound.Transport.Development {
		return nil, controlstate.ErrConfig
	}
	config.Policy.Capabilities = slices.Clone(config.Policy.Capabilities)
	config.Policy.RequiredCapabilities = slices.Clone(config.Policy.RequiredCapabilities)
	// Bootstrap deadlines agree with the ack and may only tighten defaults.
	if config.Bound.Transport.RegisterTimeout != 0 && config.Bound.Transport.RegisterTimeout != time.Duration(config.Policy.Timeouts.RegisterMS)*time.Millisecond || config.Bound.Transport.WriteTimeout != 0 && config.Bound.Transport.WriteTimeout != time.Duration(config.Policy.Timeouts.WriteMS)*time.Millisecond {
		return nil, controlstate.ErrConfig
	}
	config.Bound.Transport.RegisterTimeout = time.Duration(config.Policy.Timeouts.RegisterMS) * time.Millisecond
	config.Bound.Transport.WriteTimeout = time.Duration(config.Policy.Timeouts.WriteMS) * time.Millisecond
	if config.Bound.TickInterval < 0 || config.Bound.TickInterval > time.Second || config.Bound.MaxCommands < 0 || config.Bound.MaxCommands > 2048 {
		return nil, controlstate.ErrConfig
	}
	renewal, err := config.Renewal.normalized()
	if err != nil {
		return nil, controlstate.ErrConfig
	}
	config.Renewal = renewal
	// The pinned SDK prepays native lease and command-history accounting inside
	// BufferBytes (sessionstate README). Fund the advertised peak at startup,
	// rather than committing a registration whose ack the model must reject.
	commands := config.Bound.MaxCommands
	if commands == 0 {
		commands = 64
	}
	if config.Policy.Limits.BufferBytes < config.Policy.Limits.MaxInflight*64+commands*128 {
		return nil, controlstate.ErrConfig
	}
	gate, err := newRegistrationGate(config.Limits, config.Owner.ServiceIDs())
	if err != nil {
		return nil, err
	}
	return &DurableAdmission{config: config, gate: gate, renewSlots: make(chan struct{}, config.Limits.MaxConcurrent)}, nil
}

// Accept consumes one established QUIC connection. Peer IP comes exclusively
// from its socket address, never registration metadata or forwarded headers.
// On error the transport is closed; any admission lease is released only after
// native cleanup. The returned session still needs transport-map publication
// and EnableDispatch, and pending routes remain pending.
func (a *DurableAdmission) Accept(ctx context.Context, conn *quic.Conn) (*BoundSession, error) {
	return a.accept(ctx, conn, nil)
}

func (a *DurableAdmission) accept(ctx context.Context, conn *quic.Conn, permit func(tls.ConnectionState) error) (*BoundSession, error) {
	if conn == nil {
		return nil, controlstate.ErrConfig
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || ip.Zone() != "" {
		_ = conn.CloseWithError(quiccontrol.CodeAuthFailed, "auth_failed")
		return nil, controlstate.ErrDenied
	}
	return AcceptBound(ctx, conn, a.config.Owner.Routes(), a.config.Bound, func(ctx context.Context, state tls.ConnectionState, credential []byte, reg v1.Register) (Binding, error) {
		if permit != nil {
			if err := permit(state); err != nil {
				return Binding{}, registrationRejection(err)
			}
		}
		return a.admit(ctx, state, ip, credential, reg)
	})
}

func (a *DurableAdmission) security(ctx context.Context) (AdmissionSecurity, error) {
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	state, err := a.config.Security(bounded)
	if err != nil {
		return AdmissionSecurity{}, err
	}
	now := time.Now()
	if bounded.Err() != nil || !state.ValidUntil.After(now) || state.ValidUntil.After(now.Add(5*time.Second)) || !state.ReadyNotBefore.IsZero() && (state.ReadyNotBefore.Unix() < 0 || state.ReadyNotBefore.Unix() >= 253402300799) {
		return AdmissionSecurity{}, controlstate.ErrUnavailable
	}
	state.ValidUntil = minTime(state.ValidUntil, started.Add(5*time.Second))
	if !state.ValidUntil.After(now) {
		return AdmissionSecurity{}, controlstate.ErrUnavailable
	}
	return state, nil
}

func (a *DurableAdmission) admit(ctx context.Context, state tls.ConnectionState, ip netip.Addr, credential []byte, reg v1.Register) (Binding, error) {
	if ctx.Err() != nil {
		return Binding{}, ctx.Err()
	}
	release, err := a.gate.enter(ip)
	if err != nil {
		return Binding{}, registrationRejection(err)
	}
	defer release()
	peer, verified := peeridentity.Read(&state, a.config.TrustDomain, time.Now())
	if !verified {
		return Binding{}, registrationRejection(controlstate.ErrDenied)
	}
	if err := a.gate.service(peer.ServiceID); err != nil {
		return Binding{}, registrationRejection(err)
	}
	ack, err := a.config.Policy.prepare(reg)
	if err != nil {
		return Binding{}, err
	}
	var initial AdmissionSecurity
	guard, err := GuardRegistration(RegistrationGuard{Store: a.config.Owner.ControlStore(), TrustDomain: a.config.TrustDomain, Before: func(ctx context.Context, _ tls.ConnectionState) error {
		if err := a.config.Owner.Routes().CheckPublication(); err != nil {
			return err
		}
		var err error
		initial, err = a.security(ctx)
		return err
	}, Commit: func(ctx context.Context, _ tls.ConnectionState, reg v1.Register, lease *controlstate.RegistrationLease) (Binding, error) {
		result, err := a.config.Owner.Register(ctx, lease, reg, registry.QUIC)
		if err != nil {
			return Binding{}, err
		}
		var once sync.Once
		binding := Binding{Session: result.Session, Release: func() { once.Do(func() { _ = a.config.Owner.Routes().Disconnect(result.Session) }) }}
		current, err := a.security(ctx)
		if err != nil {
			return binding, err
		}
		expires, err := lease.Check(ctx)
		if err != nil {
			return binding, err
		}
		expires = minTime(expires, peer.Certificate.NotAfter)
		stamp := expires.Unix()
		ack.CredentialExpiresAt = &stamp
		ack.RouteRevision = v1.U64(result.RouteRevision)
		ack.Paths = nil
		for _, path := range slices.Sorted(maps.Keys(result.Paths)) {
			ack.Paths = append(ack.Paths, v1.RegisterAckPath{Path: path, State: string(result.Paths[path])})
		}
		barrier := initial.ReadyNotBefore
		if current.ReadyNotBefore.After(barrier) {
			barrier = current.ReadyNotBefore
		}
		if !barrier.IsZero() {
			ack.ReadyNotBefore = barrier.Unix()
			if barrier.Nanosecond() != 0 {
				ack.ReadyNotBefore++
			}
		}
		binding.Ack = ack
		binding.SecurityReady = true // Both explicit security assertions succeeded.
		binding.SecurityDeadline = minTime(minTime(initial.ValidUntil, current.ValidUntil), expires)
		if !time.Now().Before(binding.SecurityDeadline) || ack.ValidateForRegister(reg, v1.RegisterAckValidationOptions{}) != nil {
			return binding, controlstate.ErrUnavailable
		}
		if err := checkAckSize(ack); err != nil {
			return binding, err
		}
		binding.Renewal = a.config.Renewal
		binding.RenewSecurity = func(ctx context.Context) (SecurityLease, error) {
			// Fail closed on global checker saturation; never enqueue another query.
			select {
			case a.renewSlots <- struct{}{}:
				defer func() { <-a.renewSlots }()
			case <-ctx.Done():
				return SecurityLease{}, ctx.Err()
			default:
				return SecurityLease{}, controlstate.ErrUnavailable
			}
			started := time.Now()
			if err := a.config.Owner.Routes().CheckPublication(); err != nil {
				return SecurityLease{}, err
			}
			expires, err := lease.Check(ctx)
			if err != nil {
				return SecurityLease{}, err
			}
			health, err := a.security(ctx)
			if err != nil {
				return SecurityLease{}, err
			}
			if health.ReadyNotBefore.After(barrier) {
				// A new recovery window after the old barrier elapsed must also stop
				// already admitted flows. Re-register into the new healthy warmup.
				if !time.Now().Before(barrier) && time.Now().Before(health.ReadyNotBefore) {
					return SecurityLease{}, controlstate.ErrUnavailable
				}
				barrier = health.ReadyNotBefore
			}
			deadline := minTime(minTime(health.ValidUntil, started.Add(5*time.Second)), minTime(expires, peer.Certificate.NotAfter))
			return SecurityLease{Ready: !time.Now().Before(barrier), Deadline: deadline}, nil
		}
		return binding, nil
	}})
	if err != nil {
		return Binding{}, err
	}
	return guard(ctx, state, credential, reg)
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
