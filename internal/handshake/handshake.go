// Package handshake implements the olcrtc session handshake.
//
// The handshake runs on the first encrypted smux control stream. Frames are
// length-prefixed JSON. Protocol 4 binds a typed server identity to the fresh
// client challenge before data streams can be used.
package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/framing"
	"github.com/openlibrecommunity/olcrtc/internal/jsonstrict"
)

const (
	// ProtoVersion identifies the breaking handshake wire format.
	ProtoVersion  = 4
	challengeSize = 16
	// MaxMessageSize caps a single handshake frame.
	MaxMessageSize = 64 * 1024
	// DefaultTimeout bounds both sides of the exchange.
	DefaultTimeout = 15 * time.Second
	// ProductWire is the encrypted product record label.
	ProductWire = "OLC3"
)

// MsgType labels each handshake message.
type MsgType string

const (
	TypeHello       MsgType = "CLIENT_HELLO"
	TypeServerHello MsgType = "SERVER_HELLO"
	TypeReject      MsgType = "SERVER_REJECT"
)

// Capability is a finite server feature identifier.
type Capability string

const (
	CapabilityServerHello Capability = "server-hello-v1"
	CapabilityNotice      Capability = "notice-v1"
	CapabilityDrain       Capability = "drain-v1"
)

// MandatoryCapabilities are required by protocol 4 clients.
var MandatoryCapabilities = []Capability{ //nolint:gochecknoglobals // immutable protocol contract
	CapabilityServerHello,
	CapabilityNotice,
	CapabilityDrain,
}

// AvailabilityState is the server state advertised during the handshake.
type AvailabilityState string

const (
	AvailabilityReady       AvailabilityState = "ready"
	AvailabilityDraining    AvailabilityState = "draining"
	AvailabilityUnavailable AvailabilityState = "unavailable"
)

// AvailabilityReason is a finite, secret-free state reason.
type AvailabilityReason string

const (
	ReasonNone         AvailabilityReason = "none"
	ReasonMaintenance  AvailabilityReason = "maintenance"
	ReasonOverloaded   AvailabilityReason = "overloaded"
	ReasonRetiring     AvailabilityReason = "retiring"
	ReasonIncompatible AvailabilityReason = "incompatible"
)

// Hello is sent by the client to begin a session.
type Hello struct {
	Version   int            `json:"version"`
	Type      MsgType        `json:"type"`
	DeviceID  string         `json:"device_id"`
	Challenge string         `json:"challenge"`
	Claims    map[string]any `json:"claims,omitempty"`
}

// ServerMetadata identifies one product endpoint without transport secrets.
type ServerMetadata struct {
	Wire                   string       `json:"wire"`
	Build                  string       `json:"build"`
	ProfileID              string       `json:"profile_id"`
	CurrentProfileRevision uint64       `json:"current_profile_revision"`
	MinimumProfileRevision uint64       `json:"minimum_profile_revision"`
	EndpointID             string       `json:"endpoint_id"`
	Capabilities           []Capability `json:"capabilities"`
}

// Availability describes whether the endpoint should carry new traffic.
type Availability struct {
	State  AvailabilityState  `json:"state"`
	Reason AvailabilityReason `json:"reason"`
}

// ServerHello is the authoritative success response.
type ServerHello struct {
	Version      int            `json:"version"`
	Type         MsgType        `json:"type"`
	Challenge    string         `json:"challenge"`
	SessionID    string         `json:"session_id"`
	PeerID       string         `json:"peer_id,omitempty"`
	Server       ServerMetadata `json:"server"`
	Availability Availability   `json:"availability"`
}

// RejectCode is a stable server rejection category.
type RejectCode string

const (
	RejectMalformed       RejectCode = "malformed"
	RejectProtocolVersion RejectCode = "protocol_version"
	RejectUnauthorized    RejectCode = "unauthorized"
	RejectUnavailable     RejectCode = "server_unavailable"
	RejectIncompatible    RejectCode = "incompatible"
)

// Reject is a typed failure response with no free-form remote text.
type Reject struct {
	Version   int        `json:"version"`
	Type      MsgType    `json:"type"`
	Code      RejectCode `json:"code"`
	Challenge string     `json:"challenge,omitempty"`
}

// Expectation binds a client to its signed profile and endpoint.
type Expectation struct {
	Wire                  string
	Build                 string
	ProfileID             string
	ProfileRevision       uint64
	EndpointID            string
	MandatoryCapabilities []Capability
}

// ServerConfig supplies safe identity fields for ServerHello.
type ServerConfig struct {
	PeerID       string
	Metadata     ServerMetadata
	Availability Availability
}

var (
	ErrRejected            = errors.New("handshake rejected")
	ErrProtocolVersion     = errors.New("incompatible protocol version")
	ErrUnexpectedMessage   = errors.New("unexpected handshake message")
	ErrFrameTooLarge       = framing.ErrFrameTooLarge
	ErrChallengeMismatch   = errors.New("handshake challenge mismatch")
	ErrChallengeRequired   = errors.New("handshake challenge required")
	ErrInvalidServerHello  = errors.New("invalid server hello")
	ErrIdentityMismatch    = errors.New("server identity mismatch")
	ErrProfileOutdated     = errors.New("profile revision is no longer accepted")
	ErrMissingCapability   = errors.New("mandatory server capability missing")
	ErrInvalidAvailability = errors.New("invalid server availability")
	ErrTrailingJSON        = errors.New("trailing JSON data")
)

// RejectError carries the stable reject code returned by the server.
type RejectError struct {
	Code RejectCode
}

// ai-generated: format a typed handshake rejection with a fixed safe message.
func (e RejectError) Error() string {
	return fmt.Sprintf("%s: %s", ErrRejected, rejectMessage(e.Code))
}

// ai-generated: support errors.Is checks for typed handshake rejections.
func (e RejectError) Unwrap() error { return ErrRejected }

// AuthFunc authorizes a client and returns an opaque session ID.
type AuthFunc func(deviceID string, claims map[string]any) (sessionID string, err error)

// ai-generated: perform protocol 4 client handshake and strict identity validation.
func Client(rw io.ReadWriter, deviceID string, claims map[string]any, expected Expectation) (ServerHello, error) {
	challenge, err := newChallenge()
	if err != nil {
		return ServerHello{}, err
	}
	hello := Hello{Version: ProtoVersion, Type: TypeHello, DeviceID: deviceID, Challenge: challenge, Claims: claims}
	if err := writeFrame(rw, hello); err != nil {
		return ServerHello{}, fmt.Errorf("send hello: %w", err)
	}
	for {
		serverHello, matched, replyErr := readReply(rw, challenge)
		if !matched {
			continue
		}
		if replyErr != nil {
			return ServerHello{}, replyErr
		}
		if err := ValidateServerHello(serverHello, expected); err != nil {
			return ServerHello{}, err
		}
		return serverHello, nil
	}
}

// ai-generated: read a challenge-bound typed handshake response.
func readReply(r io.Reader, challenge string) (ServerHello, bool, error) {
	raw, err := readFrame(r)
	if err != nil {
		return ServerHello{}, true, fmt.Errorf("read server hello: %w", err)
	}
	var probe struct {
		Type      MsgType `json:"type"`
		Challenge string  `json:"challenge"`
	}
	if err := decodeStrict(raw, &probe, false); err != nil {
		return ServerHello{}, true, fmt.Errorf("parse reply: %w", err)
	}
	if probe.Challenge != challenge {
		return ServerHello{}, false, nil
	}
	switch probe.Type {
	case TypeServerHello:
		var hello ServerHello
		if err := decodeStrict(raw, &hello, true); err != nil {
			return ServerHello{}, true, fmt.Errorf("parse server hello: %w", err)
		}
		return hello, true, nil
	case TypeReject:
		return ServerHello{}, true, parseReject(raw, challenge)
	case TypeHello:
		return ServerHello{}, true, fmt.Errorf("%w: got client hello", ErrUnexpectedMessage)
	default:
		return ServerHello{}, true, fmt.Errorf("%w: got %q", ErrUnexpectedMessage, probe.Type)
	}
}

// ai-generated: validate all authoritative server identity and compatibility fields.
func ValidateServerHello(hello ServerHello, expected Expectation) error {
	if err := ValidateExpectation(expected); err != nil {
		return err
	}
	if hello.Version != ProtoVersion {
		return fmt.Errorf("%w: server v%d, client v%d", ErrProtocolVersion, hello.Version, ProtoVersion)
	}
	if hello.Type != TypeServerHello || hello.SessionID == "" || !validBuild(hello.Server.Build) {
		return ErrInvalidServerHello
	}
	if err := validateServerIdentity(hello.Server, expected); err != nil {
		return err
	}
	if err := validateRevisionWindow(hello.Server, expected.ProfileRevision); err != nil {
		return err
	}
	if err := validateCapabilities(hello.Server.Capabilities, expected.MandatoryCapabilities); err != nil {
		return err
	}
	return validateAvailability(hello.Availability)
}

// ai-generated: compare the hello identity fields against the signed expectation.
func validateServerIdentity(server ServerMetadata, expected Expectation) error {
	if server.Wire != ProductWire || expected.Wire != "" && server.Wire != expected.Wire {
		return fmt.Errorf("%w: wire", ErrIdentityMismatch)
	}
	if server.Build != expected.Build {
		return fmt.Errorf("%w: build", ErrIdentityMismatch)
	}
	if expected.ProfileID != "" && server.ProfileID != expected.ProfileID {
		return fmt.Errorf("%w: profile", ErrIdentityMismatch)
	}
	if expected.EndpointID != "" && server.EndpointID != expected.EndpointID {
		return fmt.Errorf("%w: endpoint", ErrIdentityMismatch)
	}
	return nil
}

// ai-generated: validate the advertised revision window and client membership.
func validateRevisionWindow(server ServerMetadata, clientRevision uint64) error {
	if server.CurrentProfileRevision == 0 || server.MinimumProfileRevision == 0 ||
		server.MinimumProfileRevision > server.CurrentProfileRevision {
		return ErrInvalidServerHello
	}
	if clientRevision < server.MinimumProfileRevision {
		return ErrProfileOutdated
	}
	return nil
}

// ai-generated: require every signed mandatory capability in the server hello.
func validateCapabilities(actual, required []Capability) error {
	if len(required) == 0 {
		required = MandatoryCapabilities
	}
	for _, capability := range required {
		if !slices.Contains(actual, capability) {
			return fmt.Errorf("%w: %s", ErrMissingCapability, capability)
		}
	}
	return nil
}

// ai-generated: reject incomplete client identity expectations before transport startup.
func ValidateExpectation(expected Expectation) error {
	if expected.Wire != ProductWire || !validBuild(expected.Build) || !validProfileID(expected.ProfileID) ||
		expected.ProfileRevision == 0 || expected.EndpointID == "" {
		return fmt.Errorf("%w: incomplete expectation", ErrIdentityMismatch)
	}
	required := expected.MandatoryCapabilities
	if len(required) == 0 {
		required = MandatoryCapabilities
	}
	for _, capability := range MandatoryCapabilities {
		if !slices.Contains(required, capability) {
			return fmt.Errorf("%w: %s", ErrMissingCapability, capability)
		}
	}
	return nil
}

// ai-generated: perform protocol 4 server handshake with fixed typed rejection codes.
func Server(rw io.ReadWriter, auth AuthFunc, cfg ServerConfig) (Hello, string, error) {
	raw, err := readFrame(rw)
	if err != nil {
		return Hello{}, "", fmt.Errorf("read hello: %w", err)
	}
	var hello Hello
	if decodeErr := decodeStrict(raw, &hello, true); decodeErr != nil {
		_ = writeReject(rw, RejectMalformed, "")
		return Hello{}, "", fmt.Errorf("parse hello: %w", decodeErr)
	}
	if hello.Type != TypeHello {
		_ = writeReject(rw, RejectMalformed, hello.Challenge)
		return hello, "", fmt.Errorf("%w: got %q", ErrUnexpectedMessage, hello.Type)
	}
	if hello.Version != ProtoVersion {
		_ = writeReject(rw, RejectProtocolVersion, hello.Challenge)
		return hello, "", fmt.Errorf("%w: client v%d, server v%d", ErrProtocolVersion, hello.Version, ProtoVersion)
	}
	if !validChallenge(hello.Challenge) {
		_ = writeReject(rw, RejectMalformed, hello.Challenge)
		return hello, "", ErrChallengeRequired
	}
	if configErr := ValidateServerConfig(cfg); configErr != nil {
		_ = writeReject(rw, RejectIncompatible, hello.Challenge)
		return hello, "", configErr
	}
	sessionID, err := auth(hello.DeviceID, hello.Claims)
	if err != nil {
		_ = writeReject(rw, RejectUnauthorized, hello.Challenge)
		return hello, "", fmt.Errorf("auth rejected: %w", err)
	}
	reply := ServerHello{
		Version: ProtoVersion, Type: TypeServerHello, Challenge: hello.Challenge,
		SessionID: sessionID, PeerID: cfg.PeerID, Server: cfg.Metadata, Availability: cfg.Availability,
	}
	if err := writeFrame(rw, reply); err != nil {
		return hello, sessionID, fmt.Errorf("send server hello: %w", err)
	}
	return hello, sessionID, nil
}

// ai-generated: reject invalid server startup identity before accepting sessions.
func ValidateServerConfig(cfg ServerConfig) error {
	metadata := cfg.Metadata
	if metadata.Wire != ProductWire || !validBuild(metadata.Build) || !validProfileID(metadata.ProfileID) ||
		metadata.EndpointID == "" || metadata.CurrentProfileRevision == 0 ||
		metadata.MinimumProfileRevision == 0 || metadata.MinimumProfileRevision > metadata.CurrentProfileRevision {
		return ErrInvalidServerHello
	}
	for _, capability := range MandatoryCapabilities {
		if !slices.Contains(metadata.Capabilities, capability) {
			return fmt.Errorf("%w: %s", ErrMissingCapability, capability)
		}
	}
	return validateAvailability(cfg.Availability)
}

// ai-generated: enforce the finite state and reason combinations used on the wire.
func validateAvailability(availability Availability) error {
	switch availability.State {
	case AvailabilityReady:
		if availability.Reason != ReasonNone {
			return ErrInvalidAvailability
		}
	case AvailabilityDraining, AvailabilityUnavailable:
		switch availability.Reason {
		case ReasonMaintenance, ReasonOverloaded, ReasonRetiring, ReasonIncompatible:
		case ReasonNone:
			return ErrInvalidAvailability
		default:
			return ErrInvalidAvailability
		}
	default:
		return ErrInvalidAvailability
	}
	return nil
}

// ai-generated: parse a typed rejection without accepting remote free-form text.
func parseReject(raw []byte, challenge string) error {
	var reject Reject
	if err := decodeStrict(raw, &reject, true); err != nil {
		return fmt.Errorf("parse reject: %w", err)
	}
	if reject.Version != ProtoVersion {
		return ErrProtocolVersion
	}
	if reject.Challenge != challenge {
		return ErrChallengeMismatch
	}
	if rejectMessage(reject.Code) == "" {
		return fmt.Errorf("%w: unknown reject code", ErrUnexpectedMessage)
	}
	return RejectError{Code: reject.Code}
}

// ai-generated: map stable reject codes to local safe messages.
func rejectMessage(code RejectCode) string {
	switch code {
	case RejectMalformed:
		return "malformed handshake"
	case RejectProtocolVersion:
		return "protocol upgrade required"
	case RejectUnauthorized:
		return "authorization failed"
	case RejectUnavailable:
		return "server unavailable"
	case RejectIncompatible:
		return "server incompatible"
	default:
		return ""
	}
}

// ai-generated: send a bounded typed rejection response.
func writeReject(w io.Writer, code RejectCode, challenge string) error {
	return writeFrame(w, Reject{Version: ProtoVersion, Type: TypeReject, Code: code, Challenge: challenge})
}

// ai-generated: generate a fresh 128-bit handshake challenge.
func newChallenge() (string, error) {
	var raw [challengeSize]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate handshake challenge: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// ai-generated: validate challenge encoding and entropy length.
func validChallenge(challenge string) bool {
	decoded, err := hex.DecodeString(challenge)
	return err == nil && len(decoded) == challengeSize
}

// ai-generated: require an immutable lowercase Git commit identifier.
func validBuild(build string) bool {
	if len(build) != 40 || build != strings.ToLower(build) {
		return false
	}
	decoded, err := hex.DecodeString(build)
	return err == nil && len(decoded) == 20
}

// ai-generated: require a canonical lowercase UUID without importing another package.
func validProfileID(profileID string) bool {
	if len(profileID) != 36 || profileID != strings.ToLower(profileID) {
		return false
	}
	for index, value := range profileID {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", value) {
			return false
		}
	}
	return true
}

// ai-generated: decode JSON with unknown-field and trailing-data rejection.
func decodeStrict(raw []byte, destination any, rejectUnknown bool) error {
	if err := jsonstrict.Validate(raw); err != nil {
		return fmt.Errorf("validate JSON structure: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if rejectUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrTrailingJSON
	}
	return nil
}

// ai-generated: write a bounded length-prefixed handshake JSON frame.
func writeFrame(w io.Writer, msg any) error {
	if err := framing.WriteJSON(w, msg, MaxMessageSize); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	return nil
}

// ai-generated: read a bounded length-prefixed handshake frame.
func readFrame(r io.Reader) ([]byte, error) {
	body, err := framing.ReadBytes(r, MaxMessageSize)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return body, nil
}
