//go:build !darwin && (!linux || android)

package protect

import "fmt"

// ai-generated: fail closed where explicit per-interface binding is unavailable.
func bindSocketToInterface(_ int, interfaceName string) error {
	return fmt.Errorf("interface binding is unsupported on this platform: %q", interfaceName)
}
