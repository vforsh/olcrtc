// Package diagnostic attaches safe, finite failure categories to runtime errors.
package diagnostic

import "errors"

// Category is a stable, secret-free process failure category.
type Category string

const (
	CategoryRuntime         Category = "runtime"
	CategoryConfig          Category = "config"
	CategoryProviderSetup   Category = "provider_setup"
	CategoryProviderConnect Category = "provider_connect"
	CategoryTunnelSetup     Category = "tunnel_setup"
	CategoryHandshake       Category = "handshake"
	CategoryPeerIdentity    Category = "peer_identity"
	CategoryPeerWait        Category = "peer_wait"
	CategoryLocalListener   Category = "local_listener"
)

type categorizedError struct {
	category Category
	err      error
}

func (e categorizedError) Error() string { return e.err.Error() }

func (e categorizedError) Unwrap() error { return e.err }

// ai-generated: Wrap preserves err while attaching category for the CLI exit contract.
func Wrap(category Category, err error) error {
	if err == nil {
		return nil
	}
	return categorizedError{category: category, err: err}
}

// ai-generated: CategoryOf returns the first typed category in err's unwrap chain.
func CategoryOf(err error) Category {
	var categorized categorizedError
	if errors.As(err, &categorized) {
		return categorized.category
	}
	return CategoryRuntime
}
