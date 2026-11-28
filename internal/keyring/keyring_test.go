package keyring

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
)

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func keyConfig(t *testing.T) Config {
	t.Helper()
	t.Setenv("OUTGATE_TEST_CALL_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	file := filepath.Join(t.TempDir(), "recipient ü secret")
	require(t, os.WriteFile(file, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 4096))+"\r\n"), 0600))
	return Config{Services: []string{"caller", "recipient"}, Callers: map[string][]Reference{"caller": {{ID: "shared-id", SecretEnv: "OUTGATE_TEST_CALL_KEY"}}}, Recipients: map[string]Recipient{"recipient": {ActiveKeyID: "shared-id", Keys: []Reference{{ID: "shared-id", SecretFile: file}}}}, NotAfter: time.Now().Add(time.Minute)}
}

func TestLoadBindsKeysAndDetachesStartupConfiguration(t *testing.T) {
	config := keyConfig(t)
	file := config.Recipients["recipient"].Keys[0].SecretFile
	ring, err := Load(t.Context(), config)
	require(t, err)
	defer ring.Close()
	caller, err := ring.Keys(t.Context(), httpsig.Call, "caller", "shared-id")
	require(t, err)
	recipient, err := ring.Keys(t.Context(), httpsig.Gateway, "recipient", "shared-id")
	require(t, err)
	if len(caller.Key.Secret) != 32 || len(recipient.Key.Secret) != 4096 || !recipient.NotAfter.Equal(config.NotAfter) {
		t.Fatal("incorrect accepted key")
	}
	caller.Key.Secret[0] = 99
	keys := ring.RecipientKeyIDs()
	keys["recipient"] = "changed"
	config.Callers["caller"][0].ID = "changed"
	config.Recipients["recipient"] = Recipient{}
	t.Setenv("OUTGATE_TEST_CALL_KEY", "invalid replacement")
	require(t, os.Remove(file))
	again, err := ring.Keys(t.Context(), httpsig.Call, "caller", "shared-id")
	require(t, err)
	if again.Key.Secret[0] != 1 || ring.RecipientKeyIDs()["recipient"] != "shared-id" {
		t.Fatal("mutated immutable snapshot")
	}
	before := time.Now()
	deadline, err := ring.Health(t.Context())
	require(t, err)
	if !deadline.After(before) || deadline.After(time.Now().Add(5*time.Second)) || deadline.After(config.NotAfter) {
		t.Fatal("unbounded health assertion")
	}
	for _, lookup := range [][3]string{{httpsig.Gateway, "caller", "shared-id"}, {httpsig.Call, "recipient", "shared-id"}, {httpsig.Call, "caller", "unknown"}, {"unknown", "caller", "shared-id"}} {
		if _, err := ring.Keys(t.Context(), lookup[0], lookup[1], lookup[2]); !errors.Is(err, ErrUnavailable) {
			t.Fatal("crossed key identity", err)
		}
	}
}

func TestLoadRejectsInvalidConfigurationBeforeResolvingSecrets(t *testing.T) {
	mutations := map[string]func(*Config){
		"no services":       func(c *Config) { c.Services = nil },
		"duplicate service": func(c *Config) { c.Services = append(c.Services, "caller") },
		"unknown service":   func(c *Config) { c.Callers["unknown"] = c.Callers["caller"] },
		"no keys":           func(c *Config) { c.Callers = nil; c.Recipients = nil },
		"duplicate key id":  func(c *Config) { c.Callers["caller"] = append(c.Callers["caller"], c.Callers["caller"][0]) },
		"two references":    func(c *Config) { c.Callers["caller"][0].SecretFile = "also-a-file" },
		"no reference":      func(c *Config) { c.Callers["caller"][0].SecretEnv = "" },
		"bad env":           func(c *Config) { c.Callers["caller"][0].SecretEnv = "1INVALID" },
		"oversized env":     func(c *Config) { c.Callers["caller"][0].SecretEnv = strings.Repeat("E", 129) },
		"bad id":            func(c *Config) { c.Callers["caller"][0].ID = "bad id" },
		"bad path": func(c *Config) {
			c.Recipients["recipient"] = Recipient{ActiveKeyID: "key", Keys: []Reference{{ID: "key", SecretFile: "bad\x00path"}}}
		},
		"missing active": func(c *Config) {
			p := c.Recipients["recipient"]
			p.ActiveKeyID = "missing"
			c.Recipients["recipient"] = p
		},
		"empty active": func(c *Config) { p := c.Recipients["recipient"]; p.ActiveKeyID = ""; c.Recipients["recipient"] = p },
		"expired":      func(c *Config) { c.NotAfter = time.Now().Add(-time.Second) },
		"too many per principal": func(c *Config) {
			for i := 0; i < 16; i++ {
				c.Callers["caller"] = append(c.Callers["caller"], Reference{ID: strings.Repeat("k", i+1), SecretEnv: "VALID"})
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			config := keyConfig(t)
			t.Setenv("OUTGATE_TEST_CALL_KEY", "")
			mutate(&config)
			if ring, err := Load(t.Context(), config); !errors.Is(err, ErrConfig) || ring != nil {
				if ring != nil {
					ring.Close()
				}
				t.Fatal("configuration reached secret loading", err)
			}
		})
	}
}

func TestLoadRejectsReusedSecretsAcrossIDsServicesAndLegs(t *testing.T) {
	for _, where := range []string{"same principal", "different service", "different leg"} {
		t.Run(where, func(t *testing.T) {
			config := keyConfig(t)
			reference := Reference{ID: "another-id", SecretEnv: "OUTGATE_TEST_CALL_KEY"}
			switch where {
			case "same principal":
				config.Callers["caller"] = append(config.Callers["caller"], reference)
			case "different service":
				config.Callers["recipient"] = []Reference{reference}
			case "different leg":
				config.Recipients["recipient"] = Recipient{ActiveKeyID: reference.ID, Keys: []Reference{reference}}
			}
			if ring, err := Load(t.Context(), config); !errors.Is(err, ErrConfig) || ring != nil {
				if ring != nil {
					ring.Close()
				}
				t.Fatal("reused secret accepted", err)
			}
		})
	}
}

func TestSecretDecodingIsBoundedAndStrict(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	invalid := []string{"", "not-base64!", base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), valid + " ", valid + "\n", valid[:8] + "\n" + valid[8:], valid[:len(valid)-2] + "F=", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 4097)), strings.Repeat("x", maxEncoded+1)}
	for _, encoded := range invalid {
		t.Setenv("OUTGATE_TEST_KEY", encoded)
		secret, err := readSecret(t.Context(), Reference{SecretEnv: "OUTGATE_TEST_KEY"})
		if err == nil {
			clear(secret)
			t.Fatal("accepted noncanonical/out-of-range base64")
		}
	}
	if secret, err := readSecret(t.Context(), Reference{SecretEnv: "OUTGATE_TEST_MISSING_KEY"}); err == nil {
		clear(secret)
		t.Fatal("missing environment accepted")
	}
	for _, ending := range []string{"", "\n", "\r\n"} {
		file := filepath.Join(t.TempDir(), "secret")
		require(t, os.WriteFile(file, []byte(valid+ending), 0600))
		secret, err := readSecret(t.Context(), Reference{SecretFile: file})
		require(t, err)
		if len(secret) != 32 {
			t.Fatal("wrong decoded key")
		}
		clear(secret)
	}
	for _, value := range []string{valid + "\n\n", valid + "\r", strings.Repeat("A", maxEncoded+3)} {
		file := filepath.Join(t.TempDir(), "invalid")
		require(t, os.WriteFile(file, []byte(value), 0600))
		if secret, err := readSecret(t.Context(), Reference{SecretFile: file}); err == nil {
			clear(secret)
			t.Fatal("invalid file accepted")
		}
	}
}

func TestErrorsContainNoPathsReferencesOrSecrets(t *testing.T) {
	config := keyConfig(t)
	file := filepath.Join(t.TempDir(), "private-secret-path")
	config.Callers["caller"] = []Reference{{ID: "call", SecretFile: file}}
	if _, err := Load(t.Context(), config); err != ErrUnavailable {
		t.Fatal("filesystem detail escaped", err)
	}
	require(t, os.Mkdir(file, 0700))
	if _, err := Load(t.Context(), config); err != ErrUnavailable {
		t.Fatal("directory accepted or detail escaped", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Load(ctx, config); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
}

func TestExpiryAndCloseFailClosedAndWipeOwnedBuffers(t *testing.T) {
	config := keyConfig(t)
	config.NotAfter = time.Now().Add(200 * time.Millisecond)
	ring, err := Load(t.Context(), config)
	require(t, err)
	deadline, err := ring.Health(t.Context())
	require(t, err)
	if !deadline.Equal(config.NotAfter) {
		t.Fatal("health outlived key lifetime")
	}
	time.Sleep(time.Until(config.NotAfter) + time.Millisecond)
	if _, err := ring.Keys(t.Context(), httpsig.Call, "caller", "shared-id"); err != ErrUnavailable {
		t.Fatal("expired key accepted")
	}
	if _, err := ring.Health(t.Context()); err != ErrUnavailable {
		t.Fatal("expired keyring healthy")
	}
	var owned [][]byte
	for _, secret := range ring.keys {
		owned = append(owned, secret)
	}
	require(t, ring.Close())
	require(t, ring.Close())
	for _, secret := range owned {
		for _, value := range secret {
			if value != 0 {
				t.Fatal("owned buffer not cleared")
			}
		}
	}
	if ring.RecipientKeyIDs() != nil {
		t.Fatal("closed ring returned active IDs")
	}
}

func TestConcurrentReadersAndClose(t *testing.T) {
	ring, err := Load(t.Context(), keyConfig(t))
	require(t, err)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			for j := 0; j < 100; j++ {
				key, err := ring.Keys(t.Context(), httpsig.Call, "caller", "shared-id")
				if err == nil {
					key.Key.Secret[0] = 99
				}
				_, _ = ring.Health(t.Context())
				_ = ring.RecipientKeyIDs()
			}
		})
	}
	require(t, ring.Close())
	workers.Wait()
	if _, err := ring.Health(t.Context()); err != ErrUnavailable {
		t.Fatal("closed ring healthy")
	}
}

func TestKeyringCardinalityLimitsBeforeSecretResolution(t *testing.T) {
	config := keyConfig(t)
	config.Services = make([]string, maxServices+1)
	if _, err := Load(t.Context(), config); err != ErrConfig {
		t.Fatal("service limit not enforced", err)
	}
	config = keyConfig(t)
	config.Services = nil
	config.Callers = make(map[string][]Reference)
	config.Recipients = nil
	for service := 0; service < maxKeys/maxKeysPerPrincipal+1; service++ {
		id := fmt.Sprintf("service-%d", service)
		config.Services = append(config.Services, id)
		refs := make([]Reference, maxKeysPerPrincipal)
		for key := range refs {
			refs[key] = Reference{ID: fmt.Sprintf("key-%d", key), SecretEnv: "UNRESOLVED_KEYRING_LIMIT_TEST"}
		}
		config.Callers[id] = refs
	}
	if _, err := Load(t.Context(), config); err != ErrConfig {
		t.Fatal("global key limit reached secret IO", err)
	}
}
