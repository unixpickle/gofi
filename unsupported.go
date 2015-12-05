// +build !darwin

package gofi

import (
	"errors"
)

var unsupportedError = errors.New("OS not supported.")

// DefaultInterfaceName returns the name of the default WiFi device on this machine.
// If the machine has no default WiFi device, this returns an error.
func DefaultInterfaceName() (string, error) {
	return "", errors.New("this OS is unsupported")
}

// NewHandle creates a new handle with the given interface name.
// If the handle cannot be created for any reason (e.g., permissions, no such
// device, etc.), then this returns an error.
func NewHandle(interfaceName string) (Handle, error) {
	return nil, errors.New("this OS is unsupported")
}
