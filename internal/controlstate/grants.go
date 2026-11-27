package controlstate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var ErrDenied = errors.New("outgate: grant or access denied")

func fmtDigest(value [32]byte) string { return hex.EncodeToString(value[:]) }

// IssueGrant returns the raw credential once, only after durable commit. Reusing
// the same operation returns safe metadata, including after the grant expires.
// The caller must verify artifact provenance and current deployment permissions.
func (s *Store) IssueGrant(ctx context.Context, c Change, binding GrantBinding) (IssuedGrant, error) {
	binding, err := s.grantBinding(binding, time.Time{})
	if err != nil {
		return IssuedGrant{}, err
	}
	request := struct {
		Action  string
		Change  Change
		Binding GrantBinding
	}{"grant_issued", c, binding}
	credential := ""
	encoded, fresh, err := s.securityMutation(ctx, c, "grant_issued", request, func(tx *sql.Tx, revision uint64, now time.Time) ([]byte, Target, error) {
		if _, err := s.grantBinding(binding, now); err != nil {
			return nil, Target{}, err
		}
		for _, target := range []Target{{Kind: "service", ServiceID: binding.ServiceID}, {Kind: "spki_sha256", ServiceID: binding.ServiceID, Value: binding.SPKI}} {
			revoked, err := revokedIn(ctx, tx, target)
			if err != nil {
				return nil, Target{}, err
			}
			if revoked {
				return nil, Target{}, ErrDenied
			}
		}
		var id [16]byte
		var secret [32]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, Target{}, ErrUnavailable
		}
		if _, err := rand.Read(secret[:]); err != nil {
			return nil, Target{}, ErrUnavailable
		}
		grantID := base64.RawURLEncoding.EncodeToString(id[:])
		credential = grantID + "." + base64.RawURLEncoding.EncodeToString(secret[:])
		digest := sha256.Sum256(secret[:])
		record := GrantRecord{GrantBinding: binding, GrantID: grantID, IssuedAt: now, Revision: revision}
		data, err := json.Marshal(record)
		if err != nil || len(data) > maxSecurityDocument {
			return nil, Target{}, ErrConfig
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO deployment_grants VALUES(?,?,?)", grantID, digest[:], data); err != nil {
			return nil, Target{}, ErrUnavailable
		}
		return data, Target{Kind: "grant_id", ServiceID: binding.ServiceID, Value: grantID}, nil
	})
	if err != nil {
		return IssuedGrant{}, err
	}
	var record GrantRecord
	if json.Unmarshal(encoded, &record) != nil || record.GrantID == "" || record.Revision == 0 {
		return IssuedGrant{}, ErrUnavailable
	}
	if !fresh {
		credential = ""
	}
	return IssuedGrant{Record: record, DeploymentGrant: credential}, nil
}

func revokedIn(ctx context.Context, q queryer, target Target) (bool, error) {
	var exists int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM credential_revocations WHERE service_id=? AND ((kind=? AND value=?) OR kind='service') LIMIT 1`, target.ServiceID, target.Kind, target.Value).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, ErrUnavailable
	}
	return true, nil
}

func (s *Store) readGrant(ctx context.Context, q queryer, id string) (GrantRecord, []byte, error) {
	if !(Target{Kind: "grant_id", ServiceID: "grant", Value: id}).valid() {
		return GrantRecord{}, nil, ErrDenied
	}
	var encoded, hash []byte
	err := q.QueryRowContext(ctx, "SELECT CASE WHEN length(record)<=1048576 THEN record ELSE NULL END,CASE WHEN length(secret_hash)=32 THEN secret_hash ELSE NULL END FROM deployment_grants WHERE id=?", id).Scan(&encoded, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return GrantRecord{}, nil, ErrDenied
	}
	if err != nil || len(encoded) == 0 || len(hash) != 32 {
		return GrantRecord{}, nil, ErrUnavailable
	}
	var record GrantRecord
	if json.Unmarshal(encoded, &record) != nil || record.GrantID != id || record.Revision == 0 || record.IssuedAt.IsZero() {
		return GrantRecord{}, nil, ErrUnavailable
	}
	if _, err := s.grantBinding(record.GrantBinding, record.IssuedAt); err != nil {
		return GrantRecord{}, nil, ErrUnavailable
	}
	return record, hash, nil
}

func (s *Store) grantForPeer(ctx context.Context, q queryer, id string, peer GrantPeer) (GrantRecord, []byte, error) {
	if !identifier(peer.ServiceID, 64) || !identifier(peer.InstanceID, 128) || !(Target{Kind: "spki_sha256", ServiceID: peer.ServiceID, Value: peer.SPKI}).valid() || !clean(peer.CertificateSerial, 256) {
		return GrantRecord{}, nil, ErrDenied
	}
	record, hash, err := s.readGrant(ctx, q, id)
	if err != nil {
		return GrantRecord{}, nil, err
	}
	if record.ServiceID != peer.ServiceID || record.InstanceID != peer.InstanceID || record.SPKI != peer.SPKI || !time.Now().Before(record.ExpiresAt) {
		return GrantRecord{}, nil, ErrDenied
	}
	if err := s.checkGeneration(ctx, q, record); err != nil {
		return GrantRecord{}, nil, err
	}
	for _, target := range []Target{{Kind: "grant_id", ServiceID: peer.ServiceID, Value: id}, {Kind: "spki_sha256", ServiceID: peer.ServiceID, Value: peer.SPKI}, {Kind: "certificate_serial", ServiceID: peer.ServiceID, Value: peer.CertificateSerial}} {
		revoked, err := revokedIn(ctx, q, target)
		if err != nil {
			return GrantRecord{}, nil, err
		}
		if revoked {
			return GrantRecord{}, nil, ErrDenied
		}
	}
	return record, hash, nil
}

// GrantForPeer checks public grant ID against an already verified TLS identity.
// It is not caller authentication: the listener must independently verify HMAC,
// key revocations, certificate validity and its complete service-call policy.
func (s *Store) GrantForPeer(ctx context.Context, id string, peer GrantPeer) (GrantRecord, error) {
	conn, err := s.connection(ctx)
	if err != nil {
		return GrantRecord{}, err
	}
	defer conn.Close()
	if _, err := s.metadata(ctx, conn); err != nil {
		return GrantRecord{}, err
	}
	record, _, err := s.grantForPeer(ctx, conn, id, peer)
	if err != nil {
		return GrantRecord{}, err
	}
	if err := s.checkFiles(); err != nil {
		return GrantRecord{}, err
	}
	return record, nil
}

// VerifyDeploymentGrant verifies the secret and exact registration binding.
// Registry publication, one-live-session ownership and generation high-water
// advancement require AcquireRegistration plus the registry owner transaction.
func (s *Store) VerifyDeploymentGrant(ctx context.Context, credential string, peer GrantPeer, reg v1.Register) (GrantRecord, error) {
	conn, err := s.connection(ctx)
	if err != nil {
		return GrantRecord{}, err
	}
	defer conn.Close()
	if _, err := s.metadata(ctx, conn); err != nil {
		return GrantRecord{}, err
	}
	record, err := s.verifyDeploymentGrant(ctx, conn, credential, peer, reg)
	if err != nil {
		return GrantRecord{}, err
	}
	if err := s.checkFiles(); err != nil {
		return GrantRecord{}, err
	}
	return record, nil
}

func (s *Store) verifyDeploymentGrant(ctx context.Context, q queryer, credential string, peer GrantPeer, reg v1.Register) (GrantRecord, error) {
	if len(credential) > 385 || reg.Validate() != nil {
		return GrantRecord{}, ErrDenied
	}
	id, encoded, ok := strings.Cut(credential, ".")
	if !ok || len(encoded) < 43 || len(encoded) > 256 {
		return GrantRecord{}, ErrDenied
	}
	secret, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(secret) < 32 || base64.RawURLEncoding.EncodeToString(secret) != encoded {
		return GrantRecord{}, ErrDenied
	}
	record, hash, err := s.grantForPeer(ctx, q, id, peer)
	if err != nil {
		return GrantRecord{}, err
	}
	digest := sha256.Sum256(secret)
	paths := slices.Clone(reg.Paths)
	slices.Sort(paths)
	generation := uint64(0)
	if reg.CredentialGeneration != nil {
		generation = uint64(*reg.CredentialGeneration)
	}
	if subtle.ConstantTimeCompare(digest[:], hash) != 1 || reg.ServiceID != record.ServiceID || reg.InstanceID != record.InstanceID || reg.Version != record.Version || reg.PathMode != record.PathMode || reg.RewriteMountHeaders != record.RewriteMountHeaders || !slices.Equal(paths, record.Paths) || !maps.Equal(reg.Mounts, record.Mounts) || generation != record.CredentialGeneration {
		return GrantRecord{}, ErrDenied
	}
	return record, nil
}
