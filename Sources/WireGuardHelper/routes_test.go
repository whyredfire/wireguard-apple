// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
)

type fakeRoutes struct {
	kernel map[netip.Prefix]string
	fail   map[netip.Prefix]string // the interface that the kernel refuses to route the prefix into
	ops    []string
}

func newFakeRoutes() *fakeRoutes {
	return &fakeRoutes{kernel: map[netip.Prefix]string{}, fail: map[netip.Prefix]string{}}
}

func (f *fakeRoutes) add(p netip.Prefix, ifName string) error {
	f.ops = append(f.ops, fmt.Sprintf("add %v %s", p, ifName))
	if _, ok := f.kernel[p]; ok {
		return syscall.EEXIST
	}
	if f.fail[p] == ifName {
		return syscall.ENETUNREACH
	}
	f.kernel[p] = ifName
	return nil
}

func (f *fakeRoutes) change(p netip.Prefix, ifName string) error {
	f.ops = append(f.ops, fmt.Sprintf("change %v %s", p, ifName))
	if _, ok := f.kernel[p]; !ok {
		return syscall.ESRCH
	}
	if f.fail[p] == ifName {
		return syscall.ENETUNREACH
	}
	f.kernel[p] = ifName
	return nil
}

func (f *fakeRoutes) delete(p netip.Prefix, ifName string) error {
	f.ops = append(f.ops, fmt.Sprintf("delete %v %s", p, ifName))
	if _, ok := f.kernel[p]; !ok {
		return syscall.ESRCH
	}
	delete(f.kernel, p)
	return nil
}

func (f *fakeRoutes) takeOps() []string {
	ops := f.ops
	f.ops = nil
	return ops
}

var (
	lan     = netip.MustParsePrefix("10.0.0.0/24")
	lanHost = netip.MustParsePrefix("10.0.0.7/24")
	low     = netip.MustParsePrefix("128.0.0.0/1")
	low6    = netip.MustParsePrefix("8000::/1")
	addr4   = []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}
	addr46  = []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32"), netip.MustParsePrefix("fd00::2/128")}
)

func newTestRouteTable(t *testing.T) (*routeTable, *fakeRoutes) {
	f := newFakeRoutes()
	return newRouteTable(t.Logf, f), f
}

func checkKernel(t *testing.T, f *fakeRoutes, want map[netip.Prefix]string) {
	t.Helper()
	if !maps.Equal(f.kernel, want) {
		t.Errorf("kernel routes = %v, want %v", f.kernel, want)
	}
}

func checkOps(t *testing.T, f *fakeRoutes, want ...string) {
	t.Helper()
	if got := f.takeOps(); !reflect.DeepEqual(got, want) {
		t.Errorf("route changes = %q, want %q", got, want)
	}
}

func TestRouteTableFirstInListWins(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"a", "b"})

	if err := r.claim("b", "utun-b", []netip.Prefix{lanHost, low, lan}, addr4); err != nil {
		t.Fatal(err)
	}
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-b", low: "utun-b"})
	f.takeOps()

	if err := r.claim("a", "utun-a", []netip.Prefix{lan}, addr4); err != nil {
		t.Fatal(err)
	}
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-a", low: "utun-b"})
	checkOps(t, f, "change 10.0.0.0/24 utun-a")

	r.release("a")
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-b", low: "utun-b"})
	checkOps(t, f, "change 10.0.0.0/24 utun-b")

	r.release("b")
	checkKernel(t, f, map[netip.Prefix]string{})
}

func TestRouteTableLowerInListWaits(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"a", "b"})
	r.claim("a", "utun-a", []netip.Prefix{lan}, addr4)
	f.takeOps()
	if err := r.claim("b", "utun-b", []netip.Prefix{lan}, addr4); err != nil {
		t.Fatal(err)
	}
	checkOps(t, f)
	r.release("b")
	checkOps(t, f)
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-a"})
}

func TestRouteTableReorder(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"a", "b"})
	r.claim("a", "utun-a", []netip.Prefix{lan, low}, addr4)
	r.claim("b", "utun-b", []netip.Prefix{lan}, addr4)
	f.takeOps()

	r.setOrder([]string{"b", "a"})
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-b", low: "utun-a"})
	checkOps(t, f, "change 10.0.0.0/24 utun-b")
}

func TestRouteTableUnlisted(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"c"})
	r.claim("b", "utun-b", []netip.Prefix{lan}, addr4)
	r.claim("a", "utun-a", []netip.Prefix{lan}, addr4)
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-a"})
	r.claim("c", "utun-c", []netip.Prefix{lan}, addr4)
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-c"})
}

func TestRouteTableForeignRoute(t *testing.T) {
	f := newFakeRoutes()
	var logged []string
	r := newRouteTable(func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }, f)
	f.kernel[lan] = "en0"
	if err := r.claim("a", "utun-a", []netip.Prefix{low, lan}, addr4); err != nil {
		t.Fatal(err)
	}
	checkKernel(t, f, map[netip.Prefix]string{lan: "en0", low: "utun-a"})
	for range 3 {
		r.setOrder([]string{"a"})
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "another program routes it already") {
		t.Errorf("logged %q, want the foreign route once", logged)
	}

	delete(f.kernel, lan)
	r.setOrder([]string{"a"})
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-a", low: "utun-a"})
}

func TestRouteTableRollback(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"a", "b"})
	r.claim("b", "utun-b", []netip.Prefix{low, lan}, addr4)
	f.fail[lan] = "utun-a"
	if err := r.claim("a", "utun-a", []netip.Prefix{low, lan}, addr4); err == nil {
		t.Fatal("no error")
	}
	checkKernel(t, f, map[netip.Prefix]string{low: "utun-b", lan: "utun-b"})
}

func TestRouteTableMissingFamily(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"a", "b"})
	f.fail[low6] = "utun-a"
	if err := r.claim("a", "utun-a", []netip.Prefix{low, low6}, addr4); err != nil {
		t.Fatal(err)
	}
	checkKernel(t, f, map[netip.Prefix]string{low: "utun-a"})
	if err := r.claim("b", "utun-b", []netip.Prefix{low, low6}, addr46); err != nil {
		t.Fatal(err)
	}
	checkKernel(t, f, map[netip.Prefix]string{low: "utun-a", low6: "utun-b"})

	f.fail[lan] = "utun-c"
	if err := r.claim("c", "utun-c", []netip.Prefix{lan}, addr4); err == nil {
		t.Error("refused route of the tunnel's family: no error")
	}
}

func prefixes(s string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range strings.Fields(s) {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

func kernelOf(entries ...string) map[netip.Prefix]string {
	m := map[netip.Prefix]string{}
	for _, e := range entries {
		ps, ifName, _ := strings.Cut(e, "=")
		for _, p := range prefixes(ps) {
			m[p] = ifName
		}
	}
	return m
}

func checkAddsFirst(t *testing.T, f *fakeRoutes) {
	t.Helper()
	deleting := false
	for _, op := range f.takeOps() {
		if strings.HasPrefix(op, "delete") {
			deleting = true
		} else if deleting {
			t.Errorf("%q after a route went away", op)
		}
	}
}

const default4 = "128.0.0.0/1 64.0.0.0/2 32.0.0.0/3 16.0.0.0/4 8.0.0.0/5 4.0.0.0/6 2.0.0.0/7 1.0.0.0/8"

func TestRouteTableStrictPriority(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"warp", "office"})
	if err := r.claim("office", "utun-office", prefixes("10.0.0.0/24 192.0.2.7/32"), addr4); err != nil {
		t.Fatal(err)
	}
	f.takeOps()
	if err := r.claim("warp", "utun-warp", prefixes("0.0.0.0/0"), addr4); err != nil {
		t.Fatal(err)
	}
	checkKernel(t, f, kernelOf(default4+"=utun-warp"))
	checkAddsFirst(t, f)

	r.release("warp")
	checkKernel(t, f, kernelOf("10.0.0.0/24 192.0.2.7/32=utun-office"))
	checkAddsFirst(t, f)

	r.setOrder([]string{"office", "warp"})
	r.claim("warp", "utun-warp", prefixes("0.0.0.0/0"), addr4)
	checkKernel(t, f, kernelOf(default4+"=utun-warp", "10.0.0.0/24 192.0.2.7/32=utun-office"))
}

func TestRouteTableDefaultRoutePieces(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"split", "full"})
	r.claim("split", "utun-split", prefixes("1.0.0.0/8 64.0.0.0/2 128.0.0.0/3"), addr4)
	r.claim("full", "utun-full", prefixes("0.0.0.0/0"), addr4)
	checkKernel(t, f, kernelOf("1.0.0.0/8 64.0.0.0/2 128.0.0.0/3=utun-split",
		"128.0.0.0/1 32.0.0.0/3 16.0.0.0/4 8.0.0.0/5 4.0.0.0/6 2.0.0.0/7=utun-full"))

	r.setOrder([]string{"full", "split"})
	checkKernel(t, f, kernelOf(default4+"=utun-full"))
	checkAddsFirst(t, f)
}

func TestRouteTableRetriesFailedRoutes(t *testing.T) {
	r, f := newTestRouteTable(t)
	r.setOrder([]string{"b", "a"})
	r.claim("a", "utun-a", []netip.Prefix{lan}, addr4)
	r.claim("b", "utun-b", []netip.Prefix{lan}, addr4)
	f.fail[lan] = "utun-a"
	r.setOrder([]string{"a", "b"})
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-b"})
	delete(f.fail, lan)
	r.setOrder([]string{"a", "b"})
	checkKernel(t, f, map[netip.Prefix]string{lan: "utun-a"})
}

func TestKernelPrefixes(t *testing.T) {
	for _, tc := range []struct{ allowed, routes, dropped string }{
		{"0.0.0.0/0", default4, ""},
		{"0.0.0.0/1", "64.0.0.0/2 32.0.0.0/3 16.0.0.0/4 8.0.0.0/5 4.0.0.0/6 2.0.0.0/7 1.0.0.0/8", ""},
		{"0.0.0.0/7", "1.0.0.0/8", ""},
		{"0.0.0.0/8 0.0.0.0/16", "", "0.0.0.0/8 0.0.0.0/16"},
		{"0.1.0.0/16 10.0.0.7/24 10.0.0.0/24", "0.1.0.0/16 10.0.0.0/24", ""},
		{"::/0", "8000::/1 4000::/2 2000::/3 1000::/4 800::/5 400::/6 200::/7 100::/8 64:ff9b::/96 64:ff9b:1::/48", ""},
		{"::/9", "64:ff9b::/96 64:ff9b:1::/48", "::/9"},
		{"::/96 64:ff9b::/96", "64:ff9b::/96", "::/96"},
	} {
		routes, dropped := kernelPrefixes(prefixes(tc.allowed))
		if !slices.Equal(routes, prefixes(tc.routes)) || !slices.Equal(dropped, prefixes(tc.dropped)) {
			t.Errorf("kernelPrefixes(%s) = %v, dropped %v; want %s, dropped %s", tc.allowed, routes, dropped, tc.routes, tc.dropped)
		}
	}
}
