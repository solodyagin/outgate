package controlstate

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

const maxSecurityDocument = 1 << 20

// Change carries authenticated administrative context. The Admin layer must
// check current actor scope/MFA on retries; new access changes require preview.
type Change struct {
	OperationID      string
	Actor            string
	ExpectedRevision uint64
	Reason           string
}

type GrantBinding struct {
	ServiceID            string            `json:"service_id"`
	InstanceID           string            `json:"instance_id"`
	Version              string            `json:"version"`
	Paths                []string          `json:"paths"`
	Mounts               map[string]string `json:"mounts"`
	PathMode             string            `json:"path_mode"`
	RewriteMountHeaders  bool              `json:"rewrite_mount_headers"`
	SPKI                 string            `json:"spki_sha256"`
	ArtifactDigest       string            `json:"artifact_digest"`
	ExpiresAt            time.Time         `json:"expires_at"`
	CredentialGeneration uint64            `json:"credential_generation,string,omitempty"`
}

type GrantRecord struct {
	GrantBinding
	GrantID  string    `json:"grant_id"`
	IssuedAt time.Time `json:"issued_at"`
	Revision uint64    `json:"revision,string"`
}

type IssuedGrant struct {
	Record          GrantRecord
	DeploymentGrant string // nonempty only on the first successful commit; never persist/log
}

type GrantPeer struct{ ServiceID, InstanceID, SPKI, CertificateSerial string }

type AccessPolicy struct {
	Caller           string   `json:"caller"`
	Target           string   `json:"target"`
	Paths            []string `json:"paths"`
	Methods          []string `json:"methods"`
	AllowUserContext bool     `json:"allow_user_context"`
	AllowBackground  bool     `json:"allow_background"`
}

type InternalOnly struct {
	Target  string   `json:"target"`
	Paths   []string `json:"paths"`
	Methods []string `json:"methods"`
	Callers []string `json:"callers"`
}

type AccessSnapshot struct {
	Policies     []AccessPolicy `json:"policies"`
	InternalOnly []InternalOnly `json:"internal_only"`
}

func normalizePaths(paths []string, root bool) ([]string, bool) {
	if len(paths) < 1 || len(paths) > 32 {
		return nil, false
	}
	result := slices.Clone(paths)
	total := 0
	for _, path := range result {
		total += len(path)
		normalized, err := v1.NormalizePrefix(path)
		if err != nil || normalized != path || (!root && path == "/") || total > maxSecurityDocument/12 {
			return nil, false
		}
	}
	slices.Sort(result)
	if len(slices.Compact(slices.Clone(result))) != len(result) {
		return nil, false
	}
	return result, true
}

func (s *Store) grantBinding(binding GrantBinding, now time.Time) (GrantBinding, error) {
	if !identifier(binding.ServiceID, 64) || !identifier(binding.InstanceID, 128) || !clean(binding.Version, 128) || strings.TrimSpace(binding.Version) == "" ||
		!(Target{Kind: "spki_sha256", ServiceID: binding.ServiceID, Value: binding.SPKI}).valid() || len(binding.ArtifactDigest) != 71 || !strings.HasPrefix(binding.ArtifactDigest, "sha256:") ||
		!(Target{Kind: "spki_sha256", ServiceID: binding.ServiceID, Value: strings.TrimPrefix(binding.ArtifactDigest, "sha256:")}).valid() ||
		(binding.PathMode != "strip" && binding.PathMode != "preserve") || (binding.PathMode == "preserve" && binding.RewriteMountHeaders) ||
		binding.ExpiresAt.IsZero() || !safeTimestamp(binding.ExpiresAt) || (!now.IsZero() && (!binding.ExpiresAt.After(now) || binding.ExpiresAt.Sub(now) > time.Hour)) {
		return GrantBinding{}, ErrConfig
	}
	paths, ok := normalizePaths(binding.Paths, true)
	if !ok {
		return GrantBinding{}, ErrConfig
	}
	allowed, known := s.config.Services[binding.ServiceID]
	if !known {
		return GrantBinding{}, ErrConfig
	}
	for _, path := range paths {
		permitted := false
		for _, prefix := range allowed {
			permitted = permitted || v1.PrefixAllowed(prefix, path)
		}
		if !permitted || path == "/" && binding.ServiceID != s.config.RootFrontend {
			return GrantBinding{}, ErrConfig
		}
	}
	if len(binding.Mounts) > 32 {
		return GrantBinding{}, ErrConfig
	}
	mounts := maps.Clone(binding.Mounts)
	if mounts == nil {
		mounts = map[string]string{}
	}
	budget := 4096
	for _, path := range paths {
		budget += len(path)
	}
	for id, path := range mounts {
		budget += len(id) + len(path)
		if budget > maxSecurityDocument/6 {
			return GrantBinding{}, ErrConfig
		}
		if len(id) < 1 || len(id) > 64 || id[0] < 'a' || id[0] > 'z' || !slices.Contains(paths, path) {
			return GrantBinding{}, ErrConfig
		}
		for _, c := range id {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return GrantBinding{}, ErrConfig
			}
		}
	}
	binding.Paths, binding.Mounts, binding.ExpiresAt = paths, mounts, binding.ExpiresAt.UTC()
	return binding, nil
}

func methods(values []string) ([]string, bool) {
	if len(values) < 1 || len(values) > 64 {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if len(value) < 1 || len(value) > 64 || value == "*" {
			return nil, false
		}
		for _, c := range value {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'+.^_`|~-", c)) {
				return nil, false
			}
		}
	}
	slices.Sort(result)
	return result, len(slices.Compact(slices.Clone(result))) == len(result)
}

func (s *Store) accessSnapshot(snapshot AccessSnapshot) (AccessSnapshot, error) {
	if len(snapshot.Policies) > 256 || len(snapshot.InternalOnly) > 256 {
		return AccessSnapshot{}, ErrConfig
	}
	result := AccessSnapshot{Policies: make([]AccessPolicy, 0, len(snapshot.Policies)), InternalOnly: make([]InternalOnly, 0, len(snapshot.InternalOnly))}
	budget := 0
	seen := map[string]bool{}
	for _, p := range snapshot.Policies {
		if !identifier(p.Caller, 64) || !identifier(p.Target, 64) {
			return AccessSnapshot{}, ErrConfig
		}
		if _, ok := s.config.Services[p.Caller]; !ok {
			return AccessSnapshot{}, ErrConfig
		}
		if _, ok := s.config.Services[p.Target]; !ok {
			return AccessSnapshot{}, ErrConfig
		}
		var ok bool
		p.Paths, ok = normalizePaths(p.Paths, false)
		if !ok {
			return AccessSnapshot{}, ErrConfig
		}
		p.Methods, ok = methods(p.Methods)
		if !ok {
			return AccessSnapshot{}, ErrConfig
		}
		if !p.AllowUserContext && !p.AllowBackground {
			return AccessSnapshot{}, ErrConfig
		}
		encoded, _ := json.Marshal(p)
		budget += len(encoded)
		if budget > maxSecurityDocument || seen[string(encoded)] {
			return AccessSnapshot{}, ErrConfig
		}
		seen[string(encoded)] = true
		result.Policies = append(result.Policies, p)
	}
	seen = map[string]bool{}
	for _, p := range snapshot.InternalOnly {
		if !identifier(p.Target, 64) {
			return AccessSnapshot{}, ErrConfig
		}
		if _, ok := s.config.Services[p.Target]; !ok {
			return AccessSnapshot{}, ErrConfig
		}
		var ok bool
		p.Paths, ok = normalizePaths(p.Paths, false)
		if !ok {
			return AccessSnapshot{}, ErrConfig
		}
		p.Methods, ok = methods(p.Methods)
		if !ok {
			return AccessSnapshot{}, ErrConfig
		}
		if len(p.Callers) < 1 || len(p.Callers) > 256 {
			return AccessSnapshot{}, ErrConfig
		}
		p.Callers = slices.Clone(p.Callers)
		slices.Sort(p.Callers)
		if len(slices.Compact(slices.Clone(p.Callers))) != len(p.Callers) {
			return AccessSnapshot{}, ErrConfig
		}
		for _, caller := range p.Callers {
			if _, ok := s.config.Services[caller]; !ok {
				return AccessSnapshot{}, ErrConfig
			}
		}
		encoded, _ := json.Marshal(p)
		budget += len(encoded)
		if budget > maxSecurityDocument || seen[string(encoded)] {
			return AccessSnapshot{}, ErrConfig
		}
		seen[string(encoded)] = true
		result.InternalOnly = append(result.InternalOnly, p)
	}
	// Canonical set ordering makes operation fingerprints independent of UI order.
	slices.SortFunc(result.Policies, func(a, b AccessPolicy) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return strings.Compare(string(x), string(y))
	})
	slices.SortFunc(result.InternalOnly, func(a, b InternalOnly) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return strings.Compare(string(x), string(y))
	})
	return result, nil
}

func normalizeServices(c Config) (Config, error) {
	services := make(map[string][]string, len(c.Services))
	for id, paths := range c.Services {
		if !identifier(id, 64) {
			return Config{}, ErrConfig
		}
		normalized, ok := normalizePaths(paths, true)
		if !ok {
			return Config{}, ErrConfig
		}
		services[id] = normalized
	}
	if c.RootFrontend != "" {
		if _, ok := services[c.RootFrontend]; !ok {
			return Config{}, ErrConfig
		}
	}
	c.Services = services
	return c, nil
}

func safeTimestamp(t time.Time) bool { return t.Year() >= 1 && t.Year() <= 9999 }
