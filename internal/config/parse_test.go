package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/solodyagin/outgate-sdk/httpsig"
	"github.com/solodyagin/outgate/internal/keyring"
	"go.yaml.in/yaml/v3"
)

func example(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../docs/examples/" + name + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func parsed(t *testing.T, name string) *Document {
	t.Helper()
	d, err := Parse(t.Context(), example(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestExamples(t *testing.T) {
	for _, name := range []string{"gateway.production", "gateway.windows", "gateway.development"} {
		t.Run(name, func(t *testing.T) {
			d := parsed(t, name)
			mode := "production"
			if strings.HasSuffix(name, "development") {
				mode = "development"
			}
			if d.Mode() != mode {
				t.Fatal(d.Mode())
			}
		})
	}
}
func TestStrictYAML(t *testing.T) {
	good := example(t, "gateway.development")
	for name, source := range map[string][]byte{
		"duplicate_root":   append(bytes.Clone(good), []byte("\nserver: {}\n")...),
		"duplicate_nested": []byte("server: {tls: {}, tls: {}}"),
		"nonstring_key":    []byte("true: x"),
		"sequence_key":     []byte("? [a, b]\n: c"),
		"tag":              []byte("a: !secret secret-token"),
		"explicit_bool":    []byte("a: !!bool TRUE"),
		"alias":            []byte("a: &a {b: 1}\nb: *a"),
		"cycle":            []byte("a: &a [*a]"),
		"merge":            []byte("a: {<<: {b: 1}}"),
		"documents":        append(bytes.Clone(good), []byte("\n---\n{}\n")...),
		"empty_document":   append(bytes.Clone(good), []byte("\n---\n")...),
		"malformed":        []byte("a: [secret-token"),
		"invalid_utf8":     {0xff, 0xfe},
		"too_large":        bytes.Repeat([]byte(" "), MaxBytes+1),
		"scalar":           []byte("secret-token"),
		"empty":            nil,
		"null":             []byte("null"),
		"deep":             []byte("a: " + strings.Repeat("[", maxDepth+1) + "x" + strings.Repeat("]", maxDepth+1)),
		"nodes":            []byte("a: [" + strings.Repeat("x,", maxNodes) + "x]"),
		"long_scalar":      []byte("a: " + strings.Repeat("x", maxScalar+1)),
	} {
		t.Run(name, func(t *testing.T) {
			d, err := Parse(t.Context(), source)
			if d != nil || !errors.Is(err, ErrConfig) || err.Error() != ErrConfig.Error() {
				t.Fatalf("result=%v err=%v", d, err)
			}
		})
	}
}
func TestScalarResolution(t *testing.T) {
	for source, want := range map[string]any{"on": "on", "yes": "yes", "TRUE": "TRUE", "Null": "Null", "~": "~", "2026-11-21": "2026-11-21", "0x10": "0x10", "01": "01", "1.2": "1.2", "1e3": "1e3", "true": true, "false": false, "null": nil, "": nil, "12": json.Number("12"), "99999999999999999999999999999999999999999999": json.Number("99999999999999999999999999999999999999999999"), "-12": json.Number("-12"), "\"true\"": "true", "!!str true": "true"} {
		t.Run(source, func(t *testing.T) {
			// Test scalar normalization before schema checking, including mapping keys.
			dec := yaml.NewDecoder(strings.NewReader("value: " + source))
			var root yaml.Node
			if err := dec.Decode(&root); err != nil {
				t.Fatal(err)
			}
			remaining := maxNodes
			got, err := convert(t.Context(), root.Content[0].Content[1], 0, &remaining)
			if err != nil || got != want {
				t.Fatalf("got %v (%T), want %v (%T), %v", got, got, want, want, err)
			}
		})
	}
}
func TestInvalidConfiguration(t *testing.T) {
	prod := parsed(t, "gateway.production")
	dev := parsed(t, "gateway.development")
	tests := map[string]func(map[string]any){
		"unknown_root":        func(c map[string]any) { c["secret-token"] = true },
		"unknown_nested":      func(c map[string]any) { object(c, "server")["secret-token"] = true },
		"implicit_production": func(c map[string]any) { delete(c, "deployment") },
		"zero_duration":       func(c map[string]any) { object(c, "tunnel")["connect_timeout"] = "0s" },
		"overflow_duration":   func(c map[string]any) { object(c, "tunnel")["connect_timeout"] = "999999999999h" },
		"sub_nanosecond":      func(c map[string]any) { object(c, "tunnel")["connect_timeout"] = "0.1ns" },
		"duration_type":       func(c map[string]any) { object(c, "tunnel")["connect_timeout"] = 12 },
		"both_transports_off": func(c map[string]any) {
			object(object(c, "tunnel"), "quic")["enabled"] = false
			object(object(c, "tunnel"), "wss")["enabled"] = false
		},
		"connect_budget": func(c map[string]any) { object(c, "tunnel")["connect_timeout"] = "6s" },
		"huge_budget_no_overflow": func(c map[string]any) {
			object(c, "tunnel")["connect_timeout"] = "2562047h"
			object(c, "tunnel")["tls_handshake_timeout"] = "2562047h"
		},
		"quic_heartbeat": func(c map[string]any) { object(object(c, "tunnel"), "quic")["idle_timeout"] = "15s" },
		"wss_heartbeat":  func(c map[string]any) { object(object(c, "tunnel"), "wss")["pong_timeout"] = "15s" },
		"port":           func(c map[string]any) { object(c, "server")["https_addr"] = "127.0.0.1:65536" },
		"root_reference": func(c map[string]any) { object(c, "frontend_override")["service_id"] = "absent" },
		"duplicate_prefix": func(c map[string]any) {
			object(object(c, "services"), "my-service")["allowed_paths"] = []any{"/api", "/api/"}
		},
		"root_permission": func(c map[string]any) { object(object(c, "services"), "my-service")["allowed_paths"] = []any{"/"} },
		"rollout": func(c map[string]any) {
			r := object(object(object(c, "services"), "my-service"), "rollout")
			r["canary_version"] = r["stable_version"]
		},
		"bearer_reference": func(c map[string]any) {
			array(object(c, "auth"), "bearer_tokens")[0].(map[string]any)["service_id"] = "absent"
		},
		"ap_pool": func(c map[string]any) {
			object(object(object(object(c, "services"), "reports-service"), "instance_routing"), "versions")["1.0.0"] = nil
		},
		"ap_timeout": func(c map[string]any) {
			object(object(object(object(c, "services"), "reports-service"), "instance_routing"), "readiness")["timeout"] = "5s"
		},
		"ap_status": func(c map[string]any) {
			object(object(object(object(c, "services"), "reports-service"), "instance_routing"), "readiness")["status_timeout"] = "9s"
		},
		"ap_overflow": func(c map[string]any) {
			object(object(object(object(c, "services"), "reports-service"), "instance_routing"), "readiness")["interval"] = "2562047h"
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c := dev.Values()
			change(c)
			if _, err := Parse(t.Context(), encode(t, c)); !errors.Is(err, ErrConfig) {
				t.Fatal(err)
			}
		})
	}
	for name, change := range map[string]func(map[string]any){
		"grace":           func(c map[string]any) { object(c, "deployment")["startup_grace"] = "119s" },
		"barrier":         func(c map[string]any) { object(object(c, "storage"), "replay")["recovery_barrier"] = "119s" },
		"replay_capacity": func(c map[string]any) { object(c, "interservice")["replay_cache_max_entries"] = 100 },
		"caller_capacity": func(c map[string]any) { object(c, "interservice")["replay_max_entries_per_caller"] = 999999 },
		"buffers":         func(c map[string]any) { object(object(c, "security"), "resource_limits")["buffer_bytes_global"] = 1 },
		"cert_lifetime":   func(c map[string]any) { object(c, "auth")["certificate_max_lifetime"] = "25h" },
		"grant_lifetime":  func(c map[string]any) { object(c, "auth")["grant_max_lifetime"] = "2h" },
		"cidr":            func(c map[string]any) { object(c, "server")["trusted_proxy_cidrs"] = []any{"127.0.0.1/99"} },
		"unicode_version_bytes": func(c map[string]any) {
			object(object(object(c, "services"), "my-service"), "rollout")["stable_version"] = strings.Repeat("я", 65)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := prod.Values()
			change(c)
			if _, err := Parse(t.Context(), encode(t, c)); !errors.Is(err, ErrConfig) {
				t.Fatal(err)
			}
		})
	}
	c := prod.Values()
	delete(c, "deployment")
	if d, err := Parse(t.Context(), encode(t, c)); err != nil || d.Mode() != "production" {
		t.Fatal(d, err)
	}
}
func TestSnapshotsAndKeyring(t *testing.T) {
	d := parsed(t, "gateway.production")
	v := d.Values()
	delete(v, "services")
	if len(object(d.Values(), "services")) == 0 {
		t.Fatal("mutable snapshot")
	}
	until := time.Now().Add(time.Hour)
	c, err := d.KeyringConfig(until)
	if err != nil {
		t.Fatal(err)
	}
	if !c.NotAfter.Equal(until) || len(c.Services) == 0 || len(c.Recipients) == 0 || len(c.Callers) == 0 {
		t.Fatal("mapping")
	}
	// Replace references on a detached configuration with controlled environment secrets.
	for id, refs := range c.Callers {
		for i := range refs {
			refs[i].SecretFile = ""
			refs[i].SecretEnv = fmt.Sprintf("CONFIG_TEST_CALLER_%s_%d", strings.ReplaceAll(id, "-", "_"), i)
			t.Setenv(refs[i].SecretEnv, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(1 + i + len(id))}, 32)))
		}
		c.Callers[id] = refs
	}
	counter := byte(100)
	for id, r := range c.Recipients {
		for i := range r.Keys {
			counter++
			r.Keys[i].SecretFile = ""
			r.Keys[i].SecretEnv = fmt.Sprintf("CONFIG_TEST_RECIPIENT_%s_%d", strings.ReplaceAll(id, "-", "_"), i)
			t.Setenv(r.Keys[i].SecretEnv, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{counter}, 32)))
		}
		c.Recipients[id] = r
	}
	ring, err := keyring.Load(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	for id, r := range c.Recipients {
		if ring.RecipientKeyIDs()[id] != r.ActiveKeyID {
			t.Fatal("active mapping")
		}
		if _, err := ring.Keys(t.Context(), httpsig.Gateway, id, r.ActiveKeyID); err != nil {
			t.Fatal(err)
		}
	}
	c.Services[0] = "changed"
	again, err := d.KeyringConfig(until)
	if err != nil || again.Services[0] == "changed" {
		t.Fatal("mutable keyring mapping")
	}
	if _, err := d.KeyringConfig(time.Time{}); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, d), "secret") {
			t.Fatal("format leak")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Parse(ctx, example(t, "gateway.production")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestConcurrentParse(t *testing.T) {
	source := example(t, "gateway.production")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := Parse(t.Context(), source); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}
func FuzzParse(f *testing.F) {
	for _, name := range []string{"gateway.production", "gateway.development"} {
		b, err := os.ReadFile("../../docs/examples/" + name + ".yaml")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("a: true"))
	f.Add([]byte("a: &a [*a]"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, err := Parse(t.Context(), b)
		if err != nil && !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
	})
}

func TestKeyringReferences(t *testing.T) {
	base := parsed(t, "gateway.production")
	for name, change := range map[string]func(map[string]any){
		"unknown_caller": func(c map[string]any) {
			m := object(object(c, "interservice"), "callers")
			m["absent"] = m["my-service"]
			delete(m, "my-service")
		},
		"duplicate_id": func(c map[string]any) {
			r := object(object(object(c, "interservice"), "callers"), "my-service")
			r["keys"] = append(array(r, "keys"), array(r, "keys")[0])
		},
		"active_id": func(c map[string]any) {
			object(object(object(c, "interservice"), "recipients"), "reports-service")["active_key_id"] = "absent"
		},
		"policy_target": func(c map[string]any) {
			array(object(c, "interservice"), "policies")[0].(map[string]any)["target"] = "absent"
		},
		"source_xor": func(c map[string]any) {
			array(object(object(object(c, "interservice"), "callers"), "my-service"), "keys")[0].(map[string]any)["secret_file"] = "unused.pem"
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := base.Values()
			change(v)
			if _, err := Parse(t.Context(), encode(t, v)); !errors.Is(err, ErrConfig) {
				t.Fatal(err)
			}
		})
	}
	v := base.Values()
	caller := array(object(object(object(v, "interservice"), "callers"), "my-service"), "keys")[0].(map[string]any)
	caller["secret_env"] = "CONFIG_INTEGRATION_CALL_KEY"
	t.Setenv("CONFIG_INTEGRATION_CALL_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	path := t.TempDir() + "/recipient.key"
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	recipient := object(object(object(v, "interservice"), "recipients"), "reports-service")
	array(recipient, "keys")[0].(map[string]any)["secret_file"] = path
	d, err := Parse(t.Context(), encode(t, v))
	if err != nil {
		t.Fatal(err)
	}
	config, err := d.KeyringConfig(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.Load(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer ring.Close()
	for _, test := range []struct{ leg, service, id string }{{httpsig.Call, "my-service", "my-call-1"}, {httpsig.Gateway, "reports-service", "gateway-reports-1"}} {
		if _, err := ring.Keys(t.Context(), test.leg, test.service, test.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ring.Keys(t.Context(), httpsig.Gateway, "my-service", "my-call-1"); err == nil {
		t.Fatal("cross-leg key accepted")
	}
}

// A failed regex inside negation must not turn an invalid match into acceptance.
type failedPattern struct{ failed *bool }

func (p failedPattern) String() string          { return "x" }
func (p failedPattern) MatchString(string) bool { *p.failed = true; return false }
func TestRegexFailureInNegation(t *testing.T) {
	v := &validator{}
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	c.UseRegexpEngine(func(string) (jsonschema.Regexp, error) { return failedPattern{&v.regexFailed}, nil })
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"anyOf":[{"type":"string","not":{"pattern":"x"}},{"type":"integer"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("urn:test:regex", doc); err != nil {
		t.Fatal(err)
	}
	v.schema, err = c.Compile("urn:test:regex")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.validate(t.Context(), "x"); !errors.Is(err, ErrConfig) {
		t.Fatal("regex failure accepted through negation", err)
	}
	if err := v.validate(t.Context(), 1); err != nil {
		t.Fatal("regex failure leaked into next validation", err)
	}
}
