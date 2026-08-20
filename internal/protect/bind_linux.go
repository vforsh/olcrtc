//go:build linux && !android

package protect

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ai-generated: force a Linux socket onto the selected network interface.
func bindSocketToInterface(fd int, interfaceName string) error {
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaceName); err != nil {
		return fmt.Errorf("bind socket to interface %q: %w", interfaceName, err)
	}
	return nil
}
