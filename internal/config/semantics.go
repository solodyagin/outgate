package config

import (
	"encoding/json"
	"slices"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/keyring"
)

func object(m map[string]any, key string) map[string]any { v, _ := m[key].(map[string]any); return v }
func text(m map[string]any, key, def string) string {
	v, ok := m[key].(string)
	if ok {
		return v
	}
	return def
}
func number(m map[string]any, key string, def int64) int64 {
	if v, ok := m[key].(json.Number); ok {
		n, _ := v.Int64()
		return n
	}
	return def
}
func enabled(m map[string]any, key string, def bool) bool {
	v, ok := m[key].(bool)
	if ok {
		return v
	}
	return def
}
func duration(m map[string]any, key, def string) time.Duration {
	v, _ := time.ParseDuration(text(m, key, def))
	return v
}
func array(m map[string]any, key string) []any { v, _ := m[key].([]any); return v }
func semantics(c map[string]any) error {
	services := object(c, "services")
	if len(services) > 256 {
		return ErrConfig
	}
	root := text(object(c, "frontend_override"), "service_id", "")
	if root != "" && services[root] == nil {
		return ErrConfig
	}
	strategy := text(object(c, "routing"), "strategy", "round_robin")
	for id, value := range services {
		service := value.(map[string]any)
		seen := map[string]bool{}
		for _, p := range array(service, "allowed_paths") {
			normalized, err := v1.NormalizePrefix(p.(string))
			if err != nil || seen[normalized] || normalized == "/" && id != root {
				return ErrConfig
			}
			seen[normalized] = true
		}
		rollout := object(service, "rollout")
		stable, canary := text(rollout, "stable_version", ""), text(rollout, "canary_version", "")
		if stable == canary {
			return ErrConfig
		}
		routing := object(service, "instance_routing")
		if text(routing, "strategy", strategy) == "active_passive" {
			pools := object(routing, "versions")
			percent := number(rollout, "canary_percent", 0)
			if percent != 100 && pools[stable] == nil || percent != 0 && pools[canary] == nil {
				return ErrConfig
			}
			instances := map[string]bool{}
			for _, p := range pools {
				for _, id := range array(p.(map[string]any), "instance_order") {
					s := id.(string)
					if instances[s] {
						return ErrConfig
					}
					instances[s] = true
				}
			}
			ready := object(routing, "readiness")
			interval := duration(ready, "interval", "5s")
			if duration(ready, "timeout", "2s") >= interval || duration(ready, "status_timeout", "15s")/2 < interval {
				return ErrConfig
			}
		}
	}
	tunnel := object(c, "tunnel")
	quic, wss := object(tunnel, "quic"), object(tunnel, "wss")
	if !enabled(quic, "enabled", true) && !enabled(wss, "enabled", false) {
		return ErrConfig
	}
	if enabled(quic, "enabled", true) && duration(quic, "keepalive_interval", "15s") >= duration(quic, "idle_timeout", "45s") {
		return ErrConfig
	}
	if enabled(wss, "enabled", false) && duration(wss, "pong_timeout", "10s") >= duration(wss, "ping_interval", "15s") {
		return ErrConfig
	}
	connect, handshake := duration(tunnel, "connect_timeout", "5s"), duration(tunnel, "tls_handshake_timeout", "5s")
	if connect > 10*time.Second || handshake > 10*time.Second-connect {
		return ErrConfig
	}
	access := object(c, "interservice")
	callers, recipients := object(access, "callers"), object(access, "recipients")
	total := 0
	for _, rings := range []map[string]any{callers, recipients} {
		for id, value := range rings {
			ring := value.(map[string]any)
			keys := array(ring, "keys")
			total += len(keys)
			if services[id] == nil || len(keys) > 16 || total > 1024 {
				return ErrConfig
			}
			ids := map[string]bool{}
			for _, v := range keys {
				k := text(v.(map[string]any), "key_id", "")
				if ids[k] {
					return ErrConfig
				}
				ids[k] = true
			}
			if active := text(ring, "active_key_id", ""); active != "" && !ids[active] {
				return ErrConfig
			}
		}
	}
	for _, value := range array(access, "policies") {
		p := value.(map[string]any)
		if callers[text(p, "caller", "")] == nil || recipients[text(p, "target", "")] == nil {
			return ErrConfig
		}
	}
	if text(object(c, "deployment"), "mode", "production") == "development" {
		for _, value := range array(object(c, "auth"), "bearer_tokens") {
			if services[text(value.(map[string]any), "service_id", "")] == nil {
				return ErrConfig
			}
		}
		return nil
	}
	security := object(c, "security")
	rates, resources := object(security, "rate_limits"), object(security, "resource_limits")
	capacity := number(access, "replay_cache_max_entries", 200000)
	if capacity < number(rates, "signed_per_second", 1000)*150+number(rates, "signed_burst", 2000) || number(access, "replay_max_entries_per_caller", 20000) >= capacity {
		return ErrConfig
	}
	if number(resources, "buffer_bytes_global", 536870912) < number(resources, "buffer_bytes_per_service", 67108864) || number(resources, "buffer_bytes_per_service", 67108864) < number(resources, "buffer_bytes_per_tunnel", 16777216) {
		return ErrConfig
	}
	barrier := duration(object(object(c, "storage"), "replay"), "recovery_barrier", "120s")
	if barrier < 120*time.Second || duration(object(c, "deployment"), "startup_grace", "180s") < barrier {
		return ErrConfig
	}
	auth := object(c, "auth")
	if duration(auth, "certificate_max_lifetime", "24h") > 24*time.Hour || duration(auth, "grant_max_lifetime", "1h") > time.Hour {
		return ErrConfig
	}
	return nil
}

// KeyringConfig maps HMAC references without resolving them. A finite startup
// authority lifetime is supplied separately by the deployment owner, never guessed.
// keyring.Load still validates references/secret independence before admission.
func (d *Document) KeyringConfig(notAfter time.Time) (keyring.Config, error) {
	if d == nil || d.value == nil || !notAfter.After(time.Now()) {
		return keyring.Config{}, ErrConfig
	}
	c := keyring.Config{NotAfter: notAfter, Callers: map[string][]keyring.Reference{}, Recipients: map[string]keyring.Recipient{}}
	for id := range object(d.value, "services") {
		c.Services = append(c.Services, id)
	}
	slices.Sort(c.Services)
	access := object(d.value, "interservice")
	references := func(r map[string]any) []keyring.Reference {
		keys := array(r, "keys")
		out := make([]keyring.Reference, 0, len(keys))
		for _, v := range keys {
			k := v.(map[string]any)
			out = append(out, keyring.Reference{ID: text(k, "key_id", ""), SecretEnv: text(k, "secret_env", ""), SecretFile: text(k, "secret_file", "")})
		}
		return out
	}
	for id, v := range object(access, "callers") {
		c.Callers[id] = references(v.(map[string]any))
	}
	for id, v := range object(access, "recipients") {
		r := v.(map[string]any)
		c.Recipients[id] = keyring.Recipient{ActiveKeyID: text(r, "active_key_id", ""), Keys: references(r)}
	}
	if len(c.Callers)+len(c.Recipients) == 0 {
		return keyring.Config{}, ErrConfig
	}
	return c, nil
}
