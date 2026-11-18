// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"syscall"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// TestKernelRoutes needs root:
//
//	go test -c -o /tmp/helper.test && sudo /tmp/helper.test -test.run TestKernelRoutes -test.v
func TestKernelRoutes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	a := newTestInterface(t, "198.18.0.1", "2001:2::1")
	b := newTestInterface(t, "198.18.0.2", "2001:2::2")
	k := kernelRoutes{}

	for _, tc := range []struct{ prefix, probe string }{
		{"198.19.255.0/24", "198.19.255.1"},
		{"198.19.254.7/32", "198.19.254.7"},
		{"2001:2:0:ff::/64", "2001:2:0:ff::1"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.prefix)
			t.Cleanup(func() { k.delete(p, a); k.delete(p, b) })
			if err := k.add(p, a); err != nil {
				t.Fatalf("add: %v", err)
			}
			checkRoute(t, tc.probe, a, b)
			if err := k.add(p, b); !errors.Is(err, syscall.EEXIST) {
				t.Errorf("adding it again = %v, want EEXIST", err)
			}
			if err := k.change(p, b); err != nil {
				t.Fatalf("change: %v", err)
			}
			checkRoute(t, tc.probe, b, a)
			if err := k.delete(p, b); err != nil {
				t.Fatalf("delete: %v", err)
			}
			checkRoute(t, tc.probe, "", a, b)
			if err := k.delete(p, b); !errors.Is(err, syscall.ESRCH) {
				t.Errorf("deleting it again = %v, want ESRCH", err)
			}
		})
	}

	c := newTestInterface(t, "198.18.0.3", "")
	p := netip.MustParsePrefix("2001:2:0:fe::/64")
	err := k.add(p, c)
	if err == nil {
		k.delete(p, c)
	}
	t.Logf("adding an IPv6 route into an interface without an IPv6 address: %v", err)

	if err := addLinkLocal(c, randomLinkLocal()); err != nil {
		t.Fatal(err)
	}
	if err := k.add(p, c); err != nil {
		t.Fatalf("adding an IPv6 route into an interface with only a link-local address: %v", err)
	}
	defer k.delete(p, c)
	checkRoute(t, "2001:2:0:fe::1", c)
	out, _ := exec.Command("ifconfig", c).CombinedOutput()
	t.Logf("%s", out)
}

func newTestInterface(t *testing.T, addr4, addr6 string) string {
	t.Helper()
	dev, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	name, _ := dev.Name()
	run(t, "ifconfig", name, "inet", addr4+"/32", addr4, "up")
	if addr6 != "" {
		run(t, "ifconfig", name, "inet6", addr6, "prefixlen", "128")
	}
	return name
}

var routeInterface = regexp.MustCompile(`(?m)^\s*interface: (\S+)$`)

func checkRoute(t *testing.T, addr, ifName string, others ...string) {
	t.Helper()
	family := "-inet"
	if netip.MustParseAddr(addr).Is6() {
		family = "-inet6"
	}
	out, _ := exec.Command("route", "-n", "get", family, addr).CombinedOutput()
	got := ""
	if m := routeInterface.FindSubmatch(out); m != nil {
		got = string(m[1])
	}
	if slices.Contains(others, got) || ifName != "" && got != ifName {
		t.Errorf("%s goes into %q, want %s\n%s", addr, got, ifName, out)
	}
}

func run(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}
