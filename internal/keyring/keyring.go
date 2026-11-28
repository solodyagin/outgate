// Package keyring loads a bounded, immutable deployment HMAC keyring at startup.
package keyring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	"github.com/solodyagin/outgate/internal/peeridentity"
	"github.com/solodyagin/outgate/internal/servicecall"
)

var (
	ErrConfig      = errors.New("outgate: invalid HMAC keyring configuration")
	ErrUnavailable = errors.New("outgate: HMAC keyring unavailable")
)

const (
	maxServices         = 256
	maxKeys             = 1024
	maxKeysPerPrincipal = 16
	maxSecret           = 4096
	maxEncoded          = 5464 // base64.StdEncoding.EncodedLen(maxSecret)
)

// Reference matches the hmacKey fields in config.schema.json. Exactly one source
// contains canonical padded standard base64. Files may end in one LF or CRLF.
type Reference struct {
	ID         string `json:"key_id"`
	SecretEnv  string `json:"secret_env,omitempty"`
	SecretFile string `json:"secret_file,omitempty"`
}
type Recipient struct {
	ActiveKeyID string      `json:"active_key_id"`
	Keys        []Reference `json:"keys"`
}
type Config struct {
	Services   []string // known deployment service IDs, including external-only ones
	Callers    map[string][]Reference
	Recipients map[string]Recipient
	NotAfter   time.Time // explicit accepted-key lifetime; reload/restart is external
}

type identity struct{ leg, service, id string }

// Ring is authoritative for this immutable startup configuration, not a cache
// of a remote key server. Control-state revocations are checked by StateAdmission.
// No config references, file descriptors or background workers are retained.
type Ring struct {
	mu       sync.RWMutex
	keys     map[identity][]byte
	active   map[string]string
	notAfter time.Time
	closed   bool
}

func Load(ctx context.Context, config Config) (*Ring, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validate(config); err != nil {
		return nil, err
	}
	ring := &Ring{keys: make(map[identity][]byte), active: make(map[string]string), notAfter: config.NotAfter}
	success := false
	defer func() {
		if !success {
			_ = ring.Close()
		}
	}()
	seen := make(map[[32]byte]struct{})
	load := func(leg, service string, references []Reference) error {
		for _, reference := range references {
			secret, err := readSecret(ctx, reference)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(secret)
			if _, duplicate := seen[digest]; duplicate {
				clear(secret)
				return ErrConfig
			}
			seen[digest] = struct{}{}
			ring.keys[identity{leg, service, reference.ID}] = secret
		}
		return nil
	}
	for service, references := range config.Callers {
		if err := load(httpsig.Call, service, references); err != nil {
			return nil, err
		}
	}
	for service, recipient := range config.Recipients {
		if err := load(httpsig.Gateway, service, recipient.Keys); err != nil {
			return nil, err
		}
		ring.active[service] = recipient.ActiveKeyID
	}
	if _, err := ring.Health(ctx); err != nil {
		return nil, err
	}
	success = true
	return ring, nil
}

func validate(config Config) error {
	if len(config.Services) < 1 || len(config.Services) > maxServices || len(config.Callers)+len(config.Recipients) < 1 || !config.NotAfter.After(time.Now()) {
		return ErrConfig
	}
	services := make(map[string]struct{}, len(config.Services))
	for _, id := range config.Services {
		if !peeridentity.ValidID(id, 64) {
			return ErrConfig
		}
		if _, duplicate := services[id]; duplicate {
			return ErrConfig
		}
		services[id] = struct{}{}
	}
	count := 0
	check := func(service string, references []Reference, active string) error {
		if _, known := services[service]; !known || len(references) < 1 || len(references) > maxKeysPerPrincipal {
			return ErrConfig
		}
		count += len(references)
		if count > maxKeys {
			return ErrConfig
		}
		ids := make(map[string]struct{}, len(references))
		for _, reference := range references {
			if !peeridentity.ValidID(reference.ID, 128) || (reference.SecretEnv == "") == (reference.SecretFile == "") {
				return ErrConfig
			}
			if _, duplicate := ids[reference.ID]; duplicate {
				return ErrConfig
			}
			ids[reference.ID] = struct{}{}
			if reference.SecretEnv != "" && !validEnv(reference.SecretEnv) {
				return ErrConfig
			}
			if reference.SecretFile != "" && (len(reference.SecretFile) > 4096 || strings.ContainsRune(reference.SecretFile, 0)) {
				return ErrConfig
			}
		}
		if active != "" {
			if _, known := ids[active]; !known {
				return ErrConfig
			}
		}
		return nil
	}
	for service, references := range config.Callers {
		if err := check(service, references, ""); err != nil {
			return err
		}
	}
	for service, recipient := range config.Recipients {
		if !peeridentity.ValidID(recipient.ActiveKeyID, 128) {
			return ErrConfig
		}
		if err := check(service, recipient.Keys, recipient.ActiveKeyID); err != nil {
			return err
		}
	}
	return nil
}

func validEnv(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i, c := range []byte(value) {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func readSecret(ctx context.Context, reference Reference) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var encoded []byte
	if reference.SecretEnv != "" {
		value, ok := os.LookupEnv(reference.SecretEnv)
		if !ok || len(value) < 1 || len(value) > maxEncoded {
			return nil, ErrUnavailable
		}
		encoded = []byte(value)
	} else {
		// Deployment-controlled local files only. Reject special files before open,
		// then verify the descriptor. This is not an ACL/TOCTOU filesystem sandbox.
		info, err := os.Stat(reference.SecretFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxEncoded+2 {
			return nil, ErrUnavailable
		}
		file, err := os.Open(reference.SecretFile)
		if err != nil {
			return nil, ErrUnavailable
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() < 1 || opened.Size() > maxEncoded+2 {
			return nil, ErrUnavailable
		}
		encoded, err = io.ReadAll(io.LimitReader(file, maxEncoded+3))
		if err != nil || len(encoded) != int(opened.Size()) || len(encoded) > maxEncoded+2 {
			clear(encoded)
			return nil, ErrUnavailable
		}
	}
	defer clear(encoded)
	if reference.SecretFile != "" {
		if len(encoded) > 0 && encoded[len(encoded)-1] == '\n' {
			encoded = encoded[:len(encoded)-1]
			if len(encoded) > 0 && encoded[len(encoded)-1] == '\r' {
				encoded = encoded[:len(encoded)-1]
			}
		}
	}
	if len(encoded) < 1 || len(encoded) > maxEncoded || bytes.ContainsAny(encoded, "\r\n") {
		return nil, ErrUnavailable
	}
	secret := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Strict().Decode(secret, encoded)
	if err != nil || n < 32 || n > maxSecret {
		clear(secret)
		return nil, ErrUnavailable
	}
	secret = secret[:n]
	if err := ctx.Err(); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

func (r *Ring) Keys(ctx context.Context, leg, service, id string) (servicecall.AcceptedKey, error) {
	if err := ctx.Err(); err != nil {
		return servicecall.AcceptedKey{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return servicecall.AcceptedKey{}, err
	}
	secret, ok := r.keys[identity{leg, service, id}]
	if !ok || r.closed || !r.notAfter.After(time.Now()) {
		return servicecall.AcceptedKey{}, ErrUnavailable
	}
	return servicecall.AcceptedKey{Key: delivery.Key{ID: id, Secret: slices.Clone(secret)}, NotAfter: r.notAfter}, nil
}

// Health asserts only this startup authority's lifetime and open state. It does
// not re-read files/env or check durable revocations, TLS, JWT or replay state.
func (r *Ring) Health(ctx context.Context) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	now := time.Now()
	if r.closed || !r.notAfter.After(now) {
		return time.Time{}, ErrUnavailable
	}
	deadline := now.Add(5 * time.Second)
	if r.notAfter.Before(deadline) {
		deadline = r.notAfter
	}
	return deadline, nil
}
func (r *Ring) RecipientKeyIDs() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil
	}
	return maps.Clone(r.active)
}

// Close wipes owned decoded buffers. Returned copies, environment strings and
// runtime/OS copies remain owned by their consumers. Close after runtime cleanup.
func (r *Ring) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		for id, secret := range r.keys {
			clear(secret)
			delete(r.keys, id)
		}
		clear(r.active)
	}
	return nil
}
