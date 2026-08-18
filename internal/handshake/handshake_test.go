package handshake

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/framing"
)

// ai-generated: parse the cross-language golden SERVER_HELLO through the production strict decoder.
func TestGoldenServerHelloFixture(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/olc3/server_hello.json")
	if err != nil {
		t.Fatal(err)
	}
	var hello ServerHello
	if err = decodeStrict(raw, &hello, true); err != nil {
		t.Fatal(err)
	}
	if hello.Version != ProtoVersion || hello.Type != TypeServerHello || hello.Server.Wire != ProductWire {
		t.Fatalf("golden hello = %#v", hello)
	}
}

const (
	testSessionID = "sess-42"
	testPeerID    = "1234abcd"
	testProfileID = "c0ffee00-cafe-4000-8000-000000000001"
)

var errNope = errors.New("nope")

// ai-generated: construct the complete safe identity required by protocol 4 tests.
func testServerConfig() ServerConfig {
	return ServerConfig{
		PeerID: testPeerID,
		Metadata: ServerMetadata{
			Wire: ProductWire, Build: "0123456789abcdef0123456789abcdef01234567",
			ProfileID: testProfileID, CurrentProfileRevision: 12, MinimumProfileRevision: 11,
			EndpointID: "jitsi-primary", Capabilities: MandatoryCapabilities,
		},
		Availability: Availability{State: AvailabilityReady, Reason: ReasonNone},
	}
}

// ai-generated: construct the signed-profile expectation used by protocol tests.
func testExpectation() Expectation {
	return Expectation{
		Wire: ProductWire, Build: testServerConfig().Metadata.Build,
		ProfileID: testProfileID, ProfileRevision: 11,
		EndpointID: "jitsi-primary", MandatoryCapabilities: MandatoryCapabilities,
	}
}

// ai-generated: create an in-memory client/server transport pair.
func pair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// ai-generated: prove handshake 4 returns the complete authoritative hello.
func TestHandshakeRoundTrip(t *testing.T) {
	clientConn, serverConn := pair(t)
	go func() {
		hello, sessionID, err := Server(serverConn, func(deviceID string, claims map[string]any) (string, error) {
			if deviceID != "dev-1" || claims["plan"] != "pro" {
				t.Errorf("unexpected client identity: %q %#v", deviceID, claims)
			}
			return testSessionID, nil
		}, testServerConfig())
		if err != nil || hello.DeviceID != "dev-1" || sessionID != testSessionID {
			t.Errorf("Server() = (%+v, %q, %v)", hello, sessionID, err)
		}
	}()

	hello, err := Client(clientConn, "dev-1", map[string]any{"plan": "pro"}, testExpectation())
	if err != nil {
		t.Fatalf("Client() error = %v", err)
	}
	if hello.SessionID != testSessionID || hello.PeerID != testPeerID || hello.Server.ProfileID != testProfileID {
		t.Fatalf("server hello = %#v", hello)
	}
}

// ai-generated: prove auth errors become a fixed typed rejection without remote text.
func TestHandshakeRejected(t *testing.T) {
	clientConn, serverConn := pair(t)
	go func() {
		_, _, _ = Server(serverConn, func(string, map[string]any) (string, error) {
			return "", errNope
		}, testServerConfig())
	}()
	_, err := Client(clientConn, "dev-1", nil, testExpectation())
	if !errors.Is(err, ErrRejected) || !errors.As(err, new(RejectError)) {
		t.Fatalf("Client() error = %v, want typed rejection", err)
	}
	if strings.Contains(err.Error(), errNope.Error()) {
		t.Fatalf("Client() leaked server error: %v", err)
	}
}

// ai-generated: prove a replayed reply cannot satisfy another fresh challenge.
func TestReplyMustMatchClientChallenge(t *testing.T) {
	const challengeA = "00112233445566778899aabbccddeeff"
	const challengeB = "ffeeddccbbaa99887766554433221100"
	config := testServerConfig()
	makeHello := func(challenge, session string) ServerHello {
		return ServerHello{
			Version: ProtoVersion, Type: TypeServerHello, Challenge: challenge,
			SessionID: session, PeerID: config.PeerID, Server: config.Metadata, Availability: config.Availability,
		}
	}
	var replies bytes.Buffer
	_ = writeFrame(&replies, makeHello(challengeA, "session-a"))
	_ = writeFrame(&replies, makeHello(challengeB, "session-b"))
	if _, matched, err := readReply(&replies, challengeB); err != nil || matched {
		t.Fatalf("replayed reply = matched %v, err %v", matched, err)
	}
	hello, matched, err := readReply(&replies, challengeB)
	if err != nil || !matched || hello.SessionID != "session-b" {
		t.Fatalf("matching reply = (%#v, %v, %v)", hello, matched, err)
	}
}

// ai-generated: reject a profile below the server's minimum revision.
func TestValidateServerHelloRejectsOutdatedProfile(t *testing.T) {
	config := testServerConfig()
	hello := ServerHello{
		Version: ProtoVersion, Type: TypeServerHello, SessionID: testSessionID,
		Server: config.Metadata, Availability: config.Availability,
	}
	expected := testExpectation()
	expected.ProfileRevision = 10
	if err := ValidateServerHello(hello, expected); !errors.Is(err, ErrProfileOutdated) {
		t.Fatalf("ValidateServerHello() error = %v", err)
	}
}

// ai-generated: reject unknown critical fields in a SERVER_HELLO.
func TestReadReplyRejectsUnknownField(t *testing.T) {
	const challenge = "00112233445566778899aabbccddeeff"
	raw := []byte(`{"version":4,"type":"SERVER_HELLO","challenge":"` + challenge + `","session_id":"s","peer_id":"p","server":{},"availability":{},"secret":"x"}`)
	var framed bytes.Buffer
	if err := framingWriteRaw(&framed, raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readReply(&framed, challenge); err == nil {
		t.Fatal("readReply() accepted an unknown field")
	}
}

// ai-generated: prove duplicate critical fields cannot override typed handshake identity.
func TestReadReplyRejectsDuplicateField(t *testing.T) {
	raw := []byte(`{"version":4,"version":4,"type":"SERVER_HELLO","challenge":"00112233445566778899aabbccddeeff"}`)
	var reply ServerHello
	if err := decodeStrict(raw, &reply, true); err == nil {
		t.Fatal("decodeStrict() accepted duplicate version")
	}
}

// ai-generated: write raw JSON through the production frame bounds for strict-decoder tests.
func framingWriteRaw(w io.Writer, raw []byte) error {
	return framing.WriteBytes(w, raw, MaxMessageSize)
}

// ai-generated: reject a frame length above the protocol bound.
func TestReadFrameTooLarge(t *testing.T) {
	clientConn, serverConn := pair(t)
	go func() {
		_, _ = clientConn.Write([]byte{0xff, 0xff, 0, 0})
		_ = clientConn.Close()
	}()
	_, err := readFrame(serverConn)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("readFrame() error = %v", err)
	}
}

// ai-generated: preserve EOF classification for a closed handshake stream.
func TestReadFrameEOF(t *testing.T) {
	clientConn, serverConn := pair(t)
	_ = clientConn.Close()
	_, err := readFrame(serverConn)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("readFrame() error = %v", err)
	}
}
