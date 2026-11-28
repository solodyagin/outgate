package quictunnel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
)

// RegistrationPolicy supplies explicit supported features and per-tunnel
// limits. The listener must reserve aggregate connection/memory budgets.
// Policy cannot enlarge wire maxima or the default protocol timeouts.
type RegistrationPolicy struct {
	ProtocolMinor        int
	Capabilities         []string
	RequiredCapabilities []string
	Limits               v1.RegisterAckLimits
	Timeouts             v1.RegisterAckTimeouts
	Readiness            v1.RegisterAckReadiness
}

func (p RegistrationPolicy) validate() error {
	expiry := int64(1)
	ack := v1.RegisterAck{Type: "register_ack", ProtocolVersion: 1, ProtocolMinor: p.ProtocolMinor, Capabilities: p.Capabilities, RequiredCapabilities: p.RequiredCapabilities, SessionID: "AAAAAAAAAAAAAAAAAAAAAA", Paths: []v1.RegisterAckPath{{Path: "/policy", State: "pending"}}, Limits: p.Limits, Timeouts: p.Timeouts, Readiness: p.Readiness, CredentialExpiresAt: &expiry}
	if p.ProtocolMinor > 1 || ack.Validate() != nil || checkAckSize(ack) != nil || p.Timeouts.RegisterMS > 10000 || p.Timeouts.WriteMS > 10000 || p.Timeouts.CancelAckMS > 10000 || p.Timeouts.StatusIntervalMS > 5000 || p.Timeouts.StatusStaleMS > 15000 || p.Timeouts.DrainMS > 30000 {
		return controlstate.ErrConfig
	}
	return nil
}

func (p RegistrationPolicy) prepare(reg v1.Register) (v1.RegisterAck, error) {
	if reg.Validate() != nil {
		return v1.RegisterAck{}, registrationRejection(controlstate.ErrDenied)
	}
	capabilities, err := v1.NegotiateCapabilities(p.Capabilities, p.RequiredCapabilities, reg.Capabilities, reg.RequiredCapabilities)
	if err != nil {
		return v1.RegisterAck{}, unsupportedRegistration()
	}
	required := slices.Clone(p.RequiredCapabilities)
	if reg.CredentialGeneration != nil && !slices.Contains(required, "credential_generation") {
		required = append(required, "credential_generation")
	}
	minor := min(p.ProtocolMinor, reg.ProtocolMinor)
	// Fence semantics require explicit opt-in on BOTH sides, not support alone.
	if slices.Contains(reg.RequiredCapabilities, v1.QUICQuiescentFenceCapability) != slices.Contains(required, v1.QUICQuiescentFenceCapability) {
		return v1.RegisterAck{}, unsupportedRegistration()
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return v1.RegisterAck{}, controlstate.ErrUnavailable
	}
	expiry := int64(253402300799) // Preflight only; the verified credential supplies the real expiry.
	ack := v1.RegisterAck{Type: "register_ack", ProtocolVersion: 1, ProtocolMinor: minor, Capabilities: capabilities, RequiredCapabilities: required, SessionID: base64.RawURLEncoding.EncodeToString(id[:]), RouteRevision: v1.U64(math.MaxUint64), Limits: p.Limits, Timeouts: p.Timeouts, Readiness: p.Readiness, CredentialExpiresAt: &expiry, CredentialGeneration: reg.CredentialGeneration}
	ack.Limits.MaxInflight = min(ack.Limits.MaxInflight, reg.MaxConcurrentRequests)
	for _, path := range reg.Paths {
		normalized, _ := v1.NormalizePrefix(path)
		ack.Paths = append(ack.Paths, v1.RegisterAckPath{Path: normalized, State: "pending"})
	}
	if ack.ValidateForRegister(reg, v1.RegisterAckValidationOptions{}) != nil {
		return v1.RegisterAck{}, unsupportedRegistration()
	}
	sizeCheck := ack
	sizeCheck.ReadyNotBefore = 253402300799
	if err := checkAckSize(sizeCheck); err != nil {
		return v1.RegisterAck{}, err
	}
	return ack, nil
}

func unsupportedRegistration() error {
	return &quiccontrol.Rejection{Nack: v1.RegisterNack{Type: "register_nack", Code: "unsupported_protocol_version", Detail: "registration features refused", Retryable: false}}
}

func checkAckSize(ack v1.RegisterAck) error {
	encoded, err := json.Marshal(ack)
	if err != nil || len(encoded) > ack.Limits.MaxControlBytes {
		return controlstate.ErrConfig
	}
	return nil
}
