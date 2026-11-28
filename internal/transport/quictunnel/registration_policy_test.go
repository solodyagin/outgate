package quictunnel

import (
	"errors"
	"slices"
	"testing"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
)

func registrationPolicy(t *testing.T) RegistrationPolicy {
	t.Helper()
	_, ack := Fixtures(t, true)
	return RegistrationPolicy{ProtocolMinor: 1, Capabilities: append(slices.Clone(ack.Capabilities), "credential_generation"), RequiredCapabilities: slices.Clone(ack.RequiredCapabilities), Limits: ack.Limits, Timeouts: ack.Timeouts, Readiness: ack.Readiness}
}

func TestRegistrationPolicyNegotiatesWithoutEnlargingLimits(t *testing.T) {
	reg, _ := Fixtures(t, true)
	p := registrationPolicy(t)
	must(t, p.validate())
	reg.MaxConcurrentRequests = 1
	reg.ProtocolMinor = 0
	a, err := p.prepare(reg)
	must(t, err)
	b, err := p.prepare(reg)
	must(t, err)
	if a.Limits.MaxInflight != 1 || a.ProtocolMinor != 0 || a.SessionID == b.SessionID || a.ReadyNotBefore != 0 {
		t.Fatal("bad negotiation or reused session ID")
	}
	reg.ProtocolMinor = 1
	reg.Capabilities = append(reg.Capabilities, "credential_generation")
	reg.RequiredCapabilities = append(reg.RequiredCapabilities, "credential_generation")
	generation := v1.U64(7)
	reg.CredentialGeneration = &generation
	a, err = p.prepare(reg)
	must(t, err)
	if a.CredentialGeneration == nil || !slices.Contains(a.RequiredCapabilities, "credential_generation") {
		t.Fatal("generation not required")
	}
	must(t, a.ValidateForRegister(reg, v1.RegisterAckValidationOptions{}))
}

func TestRegistrationPolicyRejectsBeforeDurableAdmission(t *testing.T) {
	for _, fault := range []string{"unsupported", "fence_one_side", "no_readiness", "small_ack"} {
		t.Run(fault, func(t *testing.T) {
			reg, _ := Fixtures(t, true)
			p := registrationPolicy(t)
			switch fault {
			case "unsupported":
				reg.Capabilities = append(reg.Capabilities, "future_feature")
				reg.RequiredCapabilities = append(reg.RequiredCapabilities, "future_feature")
			case "fence_one_side":
				reg.ProtocolMinor = 1
				reg.Capabilities = append(reg.Capabilities, v1.QUICQuiescentFenceCapability)
				reg.RequiredCapabilities = append(reg.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
				p.Capabilities = append(p.Capabilities, v1.QUICQuiescentFenceCapability)
			case "no_readiness":
				p.Readiness.Required = true
				reg.ReadinessCheckConfigured = false
			case "small_ack":
				p.Limits.MaxControlBytes = 1
			}
			_, err := p.prepare(reg)
			if fault == "small_ack" {
				if !errors.Is(err, controlstate.ErrConfig) {
					t.Fatal("oversized ack admitted", err)
				}
				return
			}
			var rejected *quiccontrol.Rejection
			if !errors.As(err, &rejected) || rejected.Nack.Code != "unsupported_protocol_version" {
				t.Fatal("unsupported policy admitted", err)
			}
		})
	}
}
