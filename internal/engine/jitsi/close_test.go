// SPDX-License-Identifier: WTFPL

package jitsi

import (
	"sync/atomic"
	"testing"
	"time"
)

// ai-generated: prove a prompt provider close does not invoke the force-close path.
func TestCloseProviderSessionPrompt(t *testing.T) {
	var forced atomic.Bool
	if closeProviderSession(func() error { return nil }, func() error {
		forced.Store(true)
		return nil
	}, time.Second, time.Second) {
		t.Fatal("prompt close was reported as forced")
	}
	if forced.Load() {
		t.Fatal("force close ran for a prompt close")
	}
}

// ai-generated: prove a wedged graceful leave is bounded and force-closes the connection.
func TestCloseProviderSessionForcesAfterDeadline(t *testing.T) {
	release := make(chan struct{})
	var forced atomic.Bool
	started := time.Now()
	if !closeProviderSession(func() error {
		<-release
		return nil
	}, func() error {
		forced.Store(true)
		close(release)
		return nil
	}, 20*time.Millisecond, time.Second) {
		t.Fatal("wedged close was not reported as forced")
	}
	if !forced.Load() {
		t.Fatal("force close did not run")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("bounded close took %v", elapsed)
	}
}
