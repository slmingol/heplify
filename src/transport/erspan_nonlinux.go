//go:build !linux

package transport

import "errors"

var errNotLinux = errors.New("erspan: raw GRE sockets require Linux")

func openRawGRESocket() (int, error)       { return -1, errNotLinux }
func closeRawSocket(fd int)                {}
func sendRaw(fd int, dstIP [4]byte, buf []byte) error { return errNotLinux }
