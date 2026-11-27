package controlstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var ErrInstanceInUse = errors.New("outgate: instance registration still owned")
var ErrRegistrationQuota = fmt.Errorf("%w: registration quota", ErrUnavailable)

// RegistrationLease owns one process-local instance until actual transport and
// handler cleanup. Generation fencing is durable; network ownership is not.
// Call Release only after cleanup, including after a failed/lost register_ack.
type RegistrationLease struct {
	Grant    GrantRecord
	store    *Store
	peer     GrantPeer
	instance string
	grantID  string
	once     sync.Once
}

func (l *RegistrationLease) Release() {
	if l == nil || l.store == nil {
		return
	}
	l.once.Do(func() {
		l.store.registrationMu.Lock()
		defer l.store.registrationMu.Unlock()
		if l.store.registrations[l.instance] == l {
			delete(l.store.registrations, l.instance)
		}
	})
}

// Check reads current grant/revocations/generation and confirms exact ownership.
// It does not renew readiness, authenticate a TLS chain or publish a route.
func (l *RegistrationLease) Check(ctx context.Context) (time.Time, error) {
	if l == nil || l.store == nil {
		return time.Time{}, ErrDenied
	}
	l.store.registrationMu.Lock()
	owned := l.store.registrations[l.instance] == l
	l.store.registrationMu.Unlock()
	if !owned {
		return time.Time{}, ErrDenied
	}
	grant, err := l.store.GrantForPeer(ctx, l.grantID, l.peer)
	if err != nil {
		return time.Time{}, err
	}
	l.store.registrationMu.Lock()
	owned = l.store.registrations[l.instance] == l
	l.store.registrationMu.Unlock()
	if !owned {
		return time.Time{}, ErrDenied
	}
	return grant.ExpiresAt, nil
}

func (s *Store) checkGeneration(ctx context.Context, q queryer, grant GrantRecord) error {
	if s.version < 3 {
		return nil
	} // explicit migration reader only; public Open requires v3
	var service, generation, id string
	err := q.QueryRowContext(ctx, `SELECT CASE WHEN length(service_id)<=64 THEN service_id ELSE NULL END,CASE WHEN length(generation)<=20 THEN generation ELSE NULL END,CASE WHEN length(grant_id)<=128 THEN grant_id ELSE NULL END FROM registration_generations WHERE instance_id=?`, grant.InstanceID).Scan(&service, &generation, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || !identifier(service, 64) || !(Target{Kind: "grant_id", ServiceID: service, Value: id}).valid() {
		return ErrUnavailable
	}
	number, err := strconv.ParseUint(generation, 10, 64)
	if err != nil || strconv.FormatUint(number, 10) != generation {
		return ErrUnavailable
	}
	if service != grant.ServiceID || grant.CredentialGeneration < number || number > 0 && grant.CredentialGeneration == number && grant.GrantID != id {
		return ErrDenied
	}
	return nil
}

// AcquireRegistration verifies the full deployment credential in the write
// transaction, atomically advancing the generation checkpoint/revision/outbox.
// Same pair may reconnect after Release; an old generation never regains access
// after a newer admission, even if register_ack or later route publication fails.
// Registration rate limits, verified TLS identity and durable registry commit
// must be supplied by the transport's admission owner.
func (s *Store) AcquireRegistration(ctx context.Context, credential string, peer GrantPeer, reg v1.Register) (*RegistrationLease, error) {
	if len(credential) > 385 || reg.Validate() != nil {
		return nil, ErrDenied
	}
	operation, err := uuid.NewV7()
	if err != nil {
		return nil, ErrUnavailable
	}
	var lease *RegistrationLease
	for attempt := 0; attempt < 3; attempt++ {
		revision, err := s.Revision(ctx)
		if err != nil {
			return nil, err
		}
		c := Change{OperationID: operation.String(), Actor: "service:" + reg.ServiceID, ExpectedRevision: revision, Reason: "credential registration"}
		// The secret and its digest never enter operation fingerprints or outbox.
		id, _, _ := strings.Cut(credential, ".")
		request := struct {
			Action, GrantID, ServiceID, InstanceID string
			Generation                             uint64
			Change                                 Change
		}{"registration_admitted", id, reg.ServiceID, reg.InstanceID, 0, c}
		if reg.CredentialGeneration != nil {
			request.Generation = uint64(*reg.CredentialGeneration)
		}
		_, _, err = s.securityMutation(ctx, c, "registration_admitted", request, func(tx *sql.Tx, next uint64, _ time.Time) ([]byte, Target, error) {
			grant, err := s.verifyDeploymentGrant(ctx, tx, credential, peer, reg)
			if err != nil {
				return nil, Target{}, err
			}
			s.registrationMu.Lock()
			defer s.registrationMu.Unlock()
			if s.registrations == nil {
				s.registrations = make(map[string]*RegistrationLease)
			}
			if s.registrations[reg.InstanceID] != nil {
				return nil, Target{}, ErrInstanceInUse
			}
			if len(s.registrations) >= s.config.MaxRegistrations {
				return nil, Target{}, ErrRegistrationQuota
			}
			lease = &RegistrationLease{Grant: grant, store: s, peer: peer, instance: reg.InstanceID, grantID: grant.GrantID}
			s.registrations[reg.InstanceID] = lease
			if _, err := tx.ExecContext(ctx, `INSERT INTO registration_generations VALUES(?,?,?,?) ON CONFLICT(instance_id) DO UPDATE SET generation=excluded.generation,grant_id=excluded.grant_id`, reg.InstanceID, reg.ServiceID, strconv.FormatUint(grant.CredentialGeneration, 10), grant.GrantID); err != nil {
				return nil, Target{}, ErrUnavailable
			}
			result, err := json.Marshal(struct {
				GrantID, InstanceID string
				Revision            uint64 `json:"revision,string"`
			}{grant.GrantID, reg.InstanceID, next})
			return result, Target{Kind: "grant_id", ServiceID: reg.ServiceID, Value: grant.GrantID}, err
		})
		if err == nil {
			return lease, nil
		}
		if lease != nil {
			lease.Release()
			lease = nil
		}
		if !errors.Is(err, ErrConflict) {
			return nil, err
		}
	}
	return nil, ErrConflict
}
