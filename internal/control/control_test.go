package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// ai-generated: parse the cross-language golden CONTROL_NOTICE through the production strict decoder.
func TestGoldenControlNoticeFixture(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/olc3/control_notice.json")
	if err != nil {
		t.Fatal(err)
	}
	message, err := parseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	notice := Notice{
		Sequence: message.Sequence, State: message.State, Reason: message.Reason,
		RetryAfterSeconds: message.RetryAfterSeconds,
	}
	if err = validateNotice(notice); err != nil {
		t.Fatal(err)
	}
	if notice.Sequence != 7 || notice.State != NoticeDraining || notice.Reason != NoticeReasonMaintenance {
		t.Fatalf("golden notice = %#v", notice)
	}
}

func controlPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

func TestRunPingPongReportsRTT(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan Health, 1)
	cfg := Config{
		Interval: 10 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
		Failures: 2,
		OnPong: func(h Health) {
			select {
			case got <- h:
			default:
			}
		},
	}
	errCh := make(chan error, 2)
	go func() { errCh <- Run(ctx, a, cfg) }()
	go func() { errCh <- Run(ctx, b, cfg) }()

	select {
	case h := <-got:
		if h.Seq == 0 {
			t.Fatal("Health.Seq = 0")
		}
		if h.RTT < 0 {
			t.Fatalf("Health.RTT = %v", h.RTT)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pong health")
	}

	cancel()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("Run() after cancel = %v", err)
		}
	}
}

func TestRunMarksUnhealthyAfterMissedPongs(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, _ = io.Copy(io.Discard, b)
	}()

	missedCh := make(chan int, 1)
	missedCallbackCh := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, a, Config{
			Interval: 10 * time.Millisecond,
			Timeout:  5 * time.Millisecond,
			Failures: 2,
			OnMissedPong: func(missed int) {
				select {
				case missedCallbackCh <- missed:
				default:
				}
			},
			OnUnhealthy: func(missed int) { missedCh <- missed },
		})
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrUnhealthy) {
			t.Fatalf("Run() error = %v, want ErrUnhealthy", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for unhealthy result")
	}
	if missed := <-missedCh; missed < 2 {
		t.Fatalf("missed = %d, want >= 2", missed)
	}
	if missed := <-missedCallbackCh; missed < 1 {
		t.Fatalf("missed callback = %d, want >= 1", missed)
	}
}

func TestRunRejectsBadProtocolVersion(t *testing.T) {
	a, b := controlPair(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(context.Background(), a, Config{Interval: time.Hour})
	}()
	if err := writeFrame(b, Message{Version: 999, Type: TypePing, Seq: 1}); err != nil {
		t.Fatalf("writeFrame() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrProtocolVersion) {
			t.Fatalf("Run() error = %v, want ErrProtocolVersion", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for protocol error")
	}
}

func TestRunStopsOnPeerClose(t *testing.T) {
	a, b := controlPair(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(context.Background(), a, Config{Interval: time.Hour})
	}()
	if err := SendClose(b); err != nil {
		t.Fatalf("SendClose() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosedByPeer) {
			t.Fatalf("Run() error = %v, want ErrClosedByPeer", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for peer close")
	}
}

func TestReadFrameRejectsTooLarge(t *testing.T) {
	a, b := controlPair(t)
	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], MaxMessageSize+1)
		_, _ = b.Write(hdr[:])
	}()
	_, err := readFrame(a)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("readFrame() error = %v, want ErrFrameTooLarge", err)
	}
}

// ai-generated: verify notice delivery does not prevent ping and pong health traffic.
func TestRunInterleavesNoticesAndPings(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notices := make(chan Notice, 2)
	gotNotice := make(chan Notice, 2)
	gotPong := make(chan Health, 1)
	errCh := make(chan error, 2)
	go func() {
		errCh <- Run(ctx, a, Config{Interval: 5 * time.Millisecond, Timeout: 100 * time.Millisecond, Notices: notices})
	}()
	go func() {
		errCh <- Run(ctx, b, Config{
			Interval: 5 * time.Millisecond, Timeout: 100 * time.Millisecond,
			OnNotice: func(notice Notice) { gotNotice <- notice },
			OnPong: func(health Health) {
				select {
				case gotPong <- health:
				default:
				}
			},
		})
	}()
	notices <- Notice{Sequence: 1, State: NoticeDraining, Reason: NoticeReasonMaintenance, RetryAfterSeconds: 30}
	notices <- Notice{Sequence: 2, State: NoticeUnavailable, Reason: NoticeReasonRetiring}
	for range 2 {
		select {
		case <-gotNotice:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for notice")
		}
	}
	select {
	case <-gotPong:
	case <-time.After(time.Second):
		t.Fatal("notices starved ping/pong")
	}
	cancel()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("Run() after cancel = %v", err)
		}
	}
}

// ai-generated: reject duplicate and out-of-order notice sequences.
func TestHandleNoticeRejectsDuplicateSequence(t *testing.T) {
	s := &state{cfg: Config{}}
	first := Message{Version: ProtoVersion, Type: TypeNotice, Sequence: 2, State: NoticeDraining, Reason: NoticeReasonMaintenance}
	if err := s.handleNotice(first); err != nil {
		t.Fatalf("first notice = %v", err)
	}
	if err := s.handleNotice(first); !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("duplicate notice = %v", err)
	}
}

// ai-generated: reject malformed notice values and structural ambiguity.
func TestParseMessageRejectsMalformedNotice(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"version":2,"type":"CONTROL_NOTICE","sequence":1,"state":"unknown","reason":"none"}`),
		[]byte(`{"version":2,"type":"CONTROL_NOTICE","sequence":1,"sequence":2,"state":"ready","reason":"none"}`),
		[]byte(`{"version":2,"type":"CONTROL_NOTICE","sequence":1,"state":"ready","reason":"none","secret":"x"}`),
	}
	for _, raw := range cases {
		message, err := parseMessage(raw)
		if err == nil {
			err = validateNotice(Notice{Sequence: message.Sequence, State: message.State, Reason: message.Reason, RetryAfterSeconds: message.RetryAfterSeconds})
		}
		if err == nil {
			t.Fatalf("accepted malformed notice: %s", raw)
		}
	}
}

// ai-generated: fuzz the production control decoder and typed notice validator.
func FuzzParseControlMessage(f *testing.F) {
	f.Add([]byte(`{"version":2,"type":"CONTROL_NOTICE","sequence":1,"state":"draining","reason":"maintenance","retry_after_seconds":30}`))
	f.Add([]byte(`{"version":2,"type":"CONTROL_NOTICE","sequence":1,"sequence":2}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		message, err := parseMessage(raw)
		if err != nil || message.Type != TypeNotice {
			return
		}
		_ = validateNotice(Notice{
			Sequence: message.Sequence, State: message.State, Reason: message.Reason,
			RetryAfterSeconds: message.RetryAfterSeconds,
		})
	})
}
