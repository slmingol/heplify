//go:build linux

package transport

import (
	"fmt"
	"syscall"
)

func openRawGRESocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_GRE)
	if err != nil {
		return -1, fmt.Errorf("socket(AF_INET, SOCK_RAW, IPPROTO_GRE): %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}
	return fd, nil
}

func closeRawSocket(fd int) {
	_ = syscall.Close(fd)
}

func sendRaw(fd int, dstIP [4]byte, buf []byte) error {
	addr := &syscall.SockaddrInet4{Addr: dstIP}
	if err := syscall.Sendto(fd, buf, 0, addr); err != nil {
		return fmt.Errorf("erspan sendto: %w", err)
	}
	return nil
}
