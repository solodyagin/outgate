// Package controlstate persists gateway control mutations. The current schema
// implements credential revocations, deployment grants and access policies.
package controlstate

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrConfig      = errors.New("outgate: invalid control configuration or command")
	ErrUnavailable = errors.New("outgate: control state unavailable")
	ErrConflict    = errors.New("outgate: control revision or operation conflict")
	ErrOutboxFull  = errors.New("outgate: control audit outbox full")
)

type Config struct {
	// Services is the trusted configured registration path allowlist.
	Services         map[string][]string
	RootFrontend     string
	Path             string
	Epoch            [32]byte // independently provisioned installation identity
	MaxRegistrations int      // default 1000 active instance owners
	MaxOutboxEvents  int      // default 100000
	MaxOutboxBytes   int64    // default 256 MiB
}

type Target struct {
	Kind      string `json:"kind"`
	ServiceID string `json:"service_id"`
	Value     string `json:"value,omitempty"`
}

type Command struct {
	OperationID      string
	Actor            string
	ExpectedRevision uint64
	Target           Target
	Reason           string
}

type Result struct {
	Target    Target    `json:"target"`
	Revision  uint64    `json:"-"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Event is an internal outbox record, not an Admin API or wire representation.
// Publisher authorization, export and acknowledgement are runtime responsibilities.
type Event struct {
	Action       string    `json:"action,omitempty"`
	OccurredAt   time.Time `json:"occurred_at,omitzero"`
	ObjectDigest string    `json:"object_sha256,omitempty"`
	OperationID  string    `json:"operation_id"`
	Actor        string    `json:"actor"`
	Revision     string    `json:"revision"`
	Target       Target    `json:"target,omitzero"`
	Reason       string    `json:"reason"`
	RevokedAt    time.Time `json:"revoked_at,omitzero"`
}

func clean(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func identifier(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for i, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}

func (t Target) valid() bool {
	if !identifier(t.ServiceID, 64) {
		return false
	}
	switch t.Kind {
	case "service":
		return t.Value == ""
	case "spki_sha256":
		if len(t.Value) != 64 {
			return false
		}
		decoded, err := hex.DecodeString(t.Value)
		return err == nil && len(decoded) == 32 && t.Value == strings.ToLower(t.Value)
	case "certificate_serial":
		return clean(t.Value, 256)
	case "grant_id":
		if len(t.Value) < 22 || len(t.Value) > 128 {
			return false
		}
		decoded, err := base64.RawURLEncoding.DecodeString(t.Value)
		return err == nil && len(t.Value) <= 128 && len(decoded) >= 16 && base64.RawURLEncoding.EncodeToString(decoded) == t.Value
	case "hmac_key_id":
		return identifier(t.Value, 128)
	default:
		return false
	}
}

func (c Command) valid(now time.Time) bool {
	return (Change{OperationID: c.OperationID, Actor: c.Actor, ExpectedRevision: c.ExpectedRevision, Reason: c.Reason}).valid(now) && c.Target.valid()
}

func (c Change) valid(now time.Time) bool {
	id, err := uuid.Parse(c.OperationID)
	if err != nil || id.String() != c.OperationID || id.Version() != 7 || id.Variant() != uuid.RFC4122 {
		return false
	}
	sec, nsec := id.Time().UnixTime()
	created := time.Unix(sec, nsec)
	return c.ExpectedRevision > 0 && clean(c.Actor, 256) && clean(c.Reason, 512) &&
		!created.After(now.Add(30*time.Second)) && !created.Before(now.Add(-30*24*time.Hour))
}
