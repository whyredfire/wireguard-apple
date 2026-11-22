// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"wireguard-helper/internal/tailscale/netmon"
)

// TestOwnChangesAreNoNetworkChange needs root, like TestKernelRoutes. A
// change to the Mac's own network while it runs makes it fail.
func TestOwnChangesAreNoNetworkChange(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	var changes atomic.Int32
	w, err := netmon.Watch(t.Logf, func() { changes.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ifName := newTestInterface(t, "198.18.0.1", "2001:2::1")
	k := kernelRoutes{}
	for _, p := range []string{"198.19.253.0/24", "2001:2:0:fd::/64"} {
		p := netip.MustParsePrefix(p)
		if err := k.add(p, ifName); err != nil {
			t.Fatal(err)
		}
		if err := k.change(p, ifName); err != nil {
			t.Fatal(err)
		}
		if err := k.delete(p, ifName); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2500 * time.Millisecond)
	if n := changes.Load(); n != 0 {
		t.Errorf("%d network changes from adding an interface and routes into it", n)
	}
}
