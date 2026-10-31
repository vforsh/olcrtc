// SPDX-License-Identifier: WTFPL

package protect

import (
	"context"
	"net"
	"net/http"
	"sync"
)

// ai-generated: let a session abort its provider sockets without a close handshake.
// ConnTracker records the connections an HTTP client dials so their owner
// can close them outright. A graceful websocket close on a socket whose
// network is gone waits out its whole handshake timeout; closing the socket
// fails that handshake at once.
type ConnTracker struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

type trackedConn struct {
	net.Conn
	tracker *ConnTracker
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.tracker.mu.Lock()
		delete(c.tracker.conns, c)
		c.tracker.mu.Unlock()
	})
	return c.Conn.Close() //nolint:wrapcheck // net.Conn semantics are preserved
}

func (t *ConnTracker) track(conn net.Conn) net.Conn {
	tracked := &trackedConn{Conn: conn, tracker: t}
	t.mu.Lock()
	if t.conns == nil {
		t.conns = make(map[*trackedConn]struct{})
	}
	t.conns[tracked] = struct{}{}
	t.mu.Unlock()
	return tracked
}

// CloseAll closes every tracked connection that is still open and reports
// how many it closed.
func (t *ConnTracker) CloseAll() int {
	t.mu.Lock()
	conns := make([]*trackedConn, 0, len(t.conns))
	for conn := range t.conns {
		conns = append(conns, conn)
	}
	t.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return len(conns)
}

// NewTrackedHTTPClient is NewHTTPClient whose dialed connections are
// recorded in tracker.
func NewTrackedHTTPClient(tracker *ConnTracker, resolvers ...*net.Resolver) *http.Client {
	base := newHTTPTransport(resolvers...)
	dial := base.DialContext
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return tracker.track(conn), nil
	}
	return &http.Client{
		Transport: &retryTransport{base: base},
		Timeout:   defaultHTTPClientTimeout,
	}
}
