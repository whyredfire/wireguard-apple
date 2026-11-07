// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package netns

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"wireguard-helper/internal/tailscale/logger"
	"wireguard-helper/internal/tailscale/netmon"
)

// Control returns a socket control function that binds sockets to the
// interface of the default route, so that they bypass the tunnels' routes.
func Control(logf logger.Logf) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return controlLogf(logf, network, address, c)
	}
}

// controlLogf binds c to a particular interface as necessary to dial the
// provided (network, address).
func controlLogf(logf logger.Logf, network, address string, c syscall.RawConn) error {
	if isLocalhost(address) {
		return nil
	}

	idx, err := netmon.DefaultRouteInterfaceIndex()
	if err != nil {
		// It's somewhat common for there to be no default gateway route
		// (e.g. on a phone with no connectivity), don't log those errors
		// since they are expected.
		if !errors.Is(err, netmon.ErrNoGatewayIndexFound) {
			logf("[unexpected] netns: DefaultRouteInterfaceIndex: %v", err)
		}
		return nil
	}

	return bindConnToInterface(c, network, address, idx, logf)
}

func bindConnToInterface(c syscall.RawConn, network, address string, ifIndex int, logf logger.Logf) error {
	v6 := strings.Contains(address, "]:") || strings.HasSuffix(network, "6") // hacky test for v6
	proto := unix.IPPROTO_IP
	opt := unix.IP_BOUND_IF
	if v6 {
		proto = unix.IPPROTO_IPV6
		opt = unix.IPV6_BOUND_IF
	}

	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), proto, opt, ifIndex)
	})
	if sockErr != nil {
		logf("[unexpected] netns: bindConnToInterface(%q, %q), v6=%v, index=%v: %v", network, address, v6, ifIndex, sockErr)
	}
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	return sockErr
}
