// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package netmon

import (
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestSkipRoutesIntoTunnels(t *testing.T) {
	m := &darwinRouteMon{logf: t.Logf}
	gateway := func(la *route.LinkAddr) *route.RouteMessage {
		return &route.RouteMessage{Type: unix.RTM_ADD, Addrs: []route.Addr{unix.RTAX_GATEWAY: la}}
	}
	for _, tc := range []struct {
		msg  *route.RouteMessage
		skip bool
	}{
		{gateway(&route.LinkAddr{Index: 35, Name: "utun7"}), true},
		{gateway(&route.LinkAddr{Index: 1 << 15}), true}, // gone
		{gateway(&route.LinkAddr{Name: "en0"}), false},
		{&route.RouteMessage{Type: unix.RTM_ADD, Index: 1}, true}, // lo0
		{&route.RouteMessage{Type: unix.RTM_ADD}, false},
	} {
		if got := m.skipRouteMessage(tc.msg); got != tc.skip {
			t.Errorf("skipRouteMessage(%+v) = %v, want %v", tc.msg.Addrs, got, tc.skip)
		}
	}
}
