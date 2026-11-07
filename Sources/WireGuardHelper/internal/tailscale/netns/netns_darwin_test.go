// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package netns

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"wireguard-helper/internal/tailscale/netmon"
)

func TestControlBindsToDefaultInterface(t *testing.T) {
	want, err := netmon.DefaultRouteInterfaceIndex()
	if err != nil {
		t.Skipf("no default route: %v", err)
	}
	lc := net.ListenConfig{Control: Control(t.Logf)}
	conn, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, _ := conn.(*net.UDPConn).SyscallConn()
	var got int
	raw.Control(func(fd uintptr) {
		got, err = unix.GetsockoptInt(int(fd), syscall.IPPROTO_IP, unix.IP_BOUND_IF)
	})
	if err != nil {
		t.Fatal(err)
	}
	iface, _ := net.InterfaceByIndex(want)
	if got != want {
		t.Errorf("bound to interface %d, want %d (%s)", got, want, iface.Name)
	}
	t.Logf("bound to %s (%d)", iface.Name, got)
}
