package quictunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
)

func TestIOFreeRuntimeSettingsValidation(t *testing.T) {
	f := runtimeFixtureConfig(t)
	admission := f.config.Admission
	admission.Owner = nil
	admission.Security = nil
	admission.TrustDomain = ""
	if err := ValidateRuntimeSettings(f.limits, admission); err != nil {
		t.Fatal("settings validator required IO-bound dependencies", err)
	}
	for _, change := range []func(*DurableAdmissionConfig){
		func(c *DurableAdmissionConfig) { c.Bound.Transport.Development = true },
		func(c *DurableAdmissionConfig) { c.Bound.Transport.RegisterTimeout = time.Second },
		func(c *DurableAdmissionConfig) { c.Limits.MaxTrackedIPs = 0 },
		func(c *DurableAdmissionConfig) { c.Limits.MaxConcurrent = 0 },
		func(c *DurableAdmissionConfig) { c.Bound.MaxCommands = 2049 },
		func(c *DurableAdmissionConfig) { c.Policy.Limits.BufferBytes = 1 },
		func(c *DurableAdmissionConfig) { c.Renewal.Interval = 2 * time.Second },
	} {
		c := admission
		change(&c)
		if err := ValidateRuntimeSettings(f.limits, c); !errors.Is(err, controlstate.ErrConfig) {
			t.Fatal("invalid settings accepted", err)
		}
	}
	if admission.Bound.Transport.RegisterTimeout != 0 || admission.Renewal.Interval != 0 {
		t.Fatal("validation mutated caller input")
	}
}
func TestConfiguredRegistrationDeadlineClosesNativeConnection(t *testing.T) {
	f := runtimeFixtureConfig(t)
	f.config.Admission.Policy.Timeouts.RegisterMS = 50
	must(t, ValidateRuntimeSettings(f.limits, f.config.Admission))
	r, packet, _ := startRuntime(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), f.client, nil)
	must(t, err)
	defer conn.CloseWithError(0, "test_complete")
	// Present a real trusted client certificate but deliberately send no stream-0
	// registration. The configured post-TLS bootstrap deadline must close it.
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("configured registration deadline not enforced")
	}
	var app *quic.ApplicationError
	if !errors.As(context.Cause(conn.Context()), &app) || app.ErrorCode != quiccontrol.CodeProtocol {
		t.Fatal("connection failed outside registration timeout boundary", context.Cause(conn.Context()))
	}
	eventually(t, func() bool { return r.Stats().Connections == 0 })
}
