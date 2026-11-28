package controlstate

import (
	"context"
	"database/sql"
	"maps"
	"slices"
	"sync"

	"github.com/google/uuid"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
)

// RegistrationOwner owns durable registration publication for one recovered
// registry. The runtime must use one owner and must not mutate its Routes through
// the RAM-only Authorized methods. Administrative mutations need their own
// authorization/publication transaction; this is not an Admin API or launcher.
type RegistrationOwner struct {
	mu      sync.Mutex
	store   *Store
	config  registry.Config
	routes  *registry.Registry
	minimum uint64
}

// OpenRegistrationOwner requires a previously explicitly bootstrapped snapshot.
// Recovery creates no live sessions and supplies no readiness/security assertion.
func OpenRegistrationOwner(ctx context.Context, store *Store, config registry.Config, minimumRevision uint64) (*RegistrationOwner, error) {
	if store == nil {
		return nil, ErrConfig
	}
	config = copyRegistryConfig(config)
	snapshot, err := store.LoadRegistry(ctx, config, minimumRevision)
	if err != nil {
		return nil, err
	}
	routes, err := registry.RestoreSnapshot(config, snapshot.Data)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &RegistrationOwner{store: store, config: config, routes: routes, minimum: snapshot.Revision}, nil
}

func copyRegistryConfig(config registry.Config) registry.Config {
	config.SharedPaths = slices.Clone(config.SharedPaths)
	config.ReservedAPIPrefixes = slices.Clone(config.ReservedAPIPrefixes)
	config.Services = maps.Clone(config.Services)
	for id, service := range config.Services {
		service.AllowedPaths = slices.Clone(service.AllowedPaths)
		if service.ActivePassive != nil {
			pool := *service.ActivePassive
			pool.Orders = maps.Clone(pool.Orders)
			for version, order := range pool.Orders {
				pool.Orders[version] = slices.Clone(order)
			}
			if pool.HoldDown != nil {
				hold := *pool.HoldDown
				pool.HoldDown = &hold
			}
			service.ActivePassive = &pool
		}
		config.Services[id] = service
	}
	return config
}

// Routes is the stable registry used by routing and transport lifecycle. Its
// handles survive later registrations and verified resync.
func (o *RegistrationOwner) Routes() *registry.Registry { return o.routes }

// Register accepts an already authenticated AcquireRegistration lease. It
// rechecks exact live ownership, current grant binding, expiry, revocations and
// generation inside the snapshot/revision/operation/outbox write transaction.
// A successful result is published but unready; ack construction, TLS validity,
// security renewal, rate limiting and cleanup remain the transport owner's job.
// On failure, the caller must release its lease after native transport cleanup.
func (o *RegistrationOwner) Register(ctx context.Context, lease *RegistrationLease, reg v1.Register, transport registry.Transport) (registry.Registration, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if lease == nil || lease.store != o.store || reg.Validate() != nil {
		return registry.Registration{}, ErrDenied
	}
	return o.routes.CommitRegistrationAuthorized(reg, transport, func(data []byte, previous uint64) error {
		revision, err := o.store.Revision(ctx)
		if err != nil {
			return err
		}
		if revision < o.minimum {
			return ErrUnavailable
		}
		o.minimum = revision
		operation, err := uuid.NewV7()
		if err != nil {
			return ErrUnavailable
		}
		change := Change{OperationID: operation.String(), Actor: "service:" + reg.ServiceID, ExpectedRevision: revision, Reason: "registry registration"}
		// Match AcquireRegistration's SQL -> ownership lock order. Keep ownership
		// pinned through commit; Release cannot race the authorization/commit gap.
		locked := false
		defer func() {
			if locked {
				o.store.registrationMu.Unlock()
			}
		}()
		committed, err := o.store.commitRegistry(ctx, change, o.config, data, &previous, func(tx *sql.Tx) error {
			o.store.registrationMu.Lock()
			locked = true
			if o.store.registrations[lease.instance] != lease {
				return ErrDenied
			}
			grant, _, err := o.store.grantForPeer(ctx, tx, lease.grantID, lease.peer)
			if err != nil {
				return err
			}
			if !registrationMatchesGrant(reg, grant) {
				return ErrDenied
			}
			return nil
		})
		if err != nil {
			return err
		}
		o.minimum = committed.Revision
		return nil
	})
}

// Resync lifts an uncertain registration barrier only after a consistent,
// verified store read at or above the retained control watermark. It never
// acknowledges the failed admission or resurrects its session. Surviving sessions
// stay unready until the runtime re-establishes their security/status freshness.
func (o *RegistrationOwner) Resync(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	snapshot, err := o.store.LoadRegistry(ctx, o.config, o.minimum)
	if err != nil {
		return err
	}
	if err := o.routes.ReconcileRegistrationAuthorized(snapshot.Data); err != nil {
		return err
	}
	o.minimum = snapshot.Revision
	return nil
}
