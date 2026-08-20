//go:build darwin

package protect

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

var errUnsupportedSocketFamily = errors.New("unsupported socket family for interface binding")

// ai-generated: force a Darwin socket onto the selected network interface.
func bindSocketToInterface(fd int, interfaceName string) error {
	ifc, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("resolve interface %q: %w", interfaceName, err)
	}
	addr, err := unix.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("inspect socket: %w", err)
	}
	switch addr.(type) {
	case *unix.SockaddrInet4:
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, ifc.Index)
	case *unix.SockaddrInet6:
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifc.Index)
	default:
		return fmt.Errorf("%w: %q", errUnsupportedSocketFamily, interfaceName)
	}
	if err != nil {
		return fmt.Errorf("bind socket to interface %q: %w", interfaceName, err)
	}
	return nil
}
