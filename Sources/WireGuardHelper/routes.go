// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"sync"
	"syscall"

	"wireguard-helper/internal/tailscale/logger"
)

// routeSystem changes the kernel's routes into the tunnels' interfaces.
type routeSystem interface {
	add(p netip.Prefix, ifName string) error
	change(p netip.Prefix, ifName string) error
	delete(p netip.Prefix, ifName string) error
}

// routeTable shares the routes among the tunnels: a route goes in only when
// no tunnel before it in the app's list routes all of its prefix.
type routeTable struct {
	logf   logger.Logf
	sys    routeSystem
	mu     sync.Mutex
	order  map[string]int // the tunnels' positions in the app's list
	claims map[string]*claim
	routes map[netip.Prefix]installedRoute
}

type claim struct {
	ifName     string
	routes     []netip.Prefix
	routed     map[netip.Prefix]bool   // the routes, for looking them up
	has4, has6 bool                    // whether the tunnel has an address of the family
	failed     map[netip.Prefix]bool   // the routes the kernel didn't take for this tunnel
	logged     map[netip.Prefix]string // the last failure logged for each route, so it's logged once
}

type installedRoute struct {
	tunnel string
	ifName string
}

func newRouteTable(logf logger.Logf, sys routeSystem) *routeTable {
	return &routeTable{logf: logf, sys: sys, claims: map[string]*claim{}, routes: map[netip.Prefix]installedRoute{}}
}

func (r *routeTable) position(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.positionLocked(name)
}

func (r *routeTable) positionLocked(name string) int {
	if position, ok := r.order[name]; ok {
		return position
	}
	return math.MaxInt
}

func (r *routeTable) before(a, b string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.beforeLocked(a, b)
}

func (r *routeTable) beforeLocked(a, b string) bool {
	pa, pb := r.positionLocked(a), r.positionLocked(b)
	return pa < pb || pa == pb && a < b
}

func (r *routeTable) setOrder(names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = make(map[string]int, len(names))
	for i, name := range names {
		r.order[name] = i
	}
	r.sync("")
}

func (r *routeTable) claim(name, ifName string, allowed, addrs []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := &claim{ifName: ifName, failed: map[netip.Prefix]bool{}, logged: map[netip.Prefix]string{}}
	for _, addr := range addrs {
		if addr.Addr().Is4() {
			c.has4 = true
		} else {
			c.has6 = true
		}
	}
	var dropped []netip.Prefix
	c.routes, dropped = kernelPrefixes(allowed)
	c.routed = make(map[netip.Prefix]bool, len(c.routes))
	for _, p := range c.routes {
		c.routed[p] = true
	}
	for _, p := range dropped {
		r.logf("%s: not routing %v, as a route for the unspecified address breaks the default route", name, p)
	}
	r.claims[name] = c
	if err := r.sync(name); err != nil {
		delete(r.claims, name)
		r.sync("")
		return err
	}
	return nil
}

// release comes before the tunnel's interface goes away, so that its routes
// move to the next tunnels without a gap.
func (r *routeTable) release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claims[name] != nil {
		delete(r.claims, name)
		r.sync("")
	}
}

func (r *routeTable) wanted() map[netip.Prefix]string {
	want := map[netip.Prefix]string{}
	for name, c := range r.claims {
		for _, p := range c.routes {
			if !c.failed[p] && !r.coveredBefore(name, p) {
				want[p] = name
			}
		}
	}
	return want
}

func (r *routeTable) coveredBefore(name string, p netip.Prefix) bool {
	for other, c := range r.claims {
		if other == name || !r.beforeLocked(other, name) {
			continue
		}
		for bits := 0; bits <= p.Bits(); bits++ {
			if q := netip.PrefixFrom(p.Addr(), bits).Masked(); c.routed[q] && !c.failed[q] {
				return true
			}
		}
	}
	return false
}

func (c *claim) hasFamily(p netip.Prefix) bool {
	return p.Addr().Is4() && c.has4 || p.Addr().Is6() && c.has6
}

// sync adds and moves routes before removing any, so that traffic doesn't
// take the default route in between.
func (r *routeTable) sync(starting string) error {
	for _, c := range r.claims {
		maps.DeleteFunc(c.failed, func(p netip.Prefix, _ bool) bool { return c.hasFamily(p) })
	}
	for {
		want := r.wanted()
		retry := false
		for _, p := range slices.SortedFunc(maps.Keys(want), netip.Prefix.Compare) {
			name := want[p]
			if r.routes[p].tunnel == name {
				continue
			}
			c := r.claims[name]
			err := r.point(p, name)
			if err == nil {
				delete(c.logged, p)
				continue
			}
			foreign := errors.Is(err, syscall.EEXIST)
			if foreign {
				err = fmt.Errorf("routing %v into %s: another program routes it already", p, name)
			} else {
				err = fmt.Errorf("routing %v into %s: %w", p, name, err)
			}
			if name == starting && c.hasFamily(p) && !foreign {
				return err
			}
			if c.logged[p] != err.Error() {
				r.logf("%v; leaving it", err)
				c.logged[p] = err.Error()
			}
			c.failed[p] = true
			retry = true
			break
		}
		if retry {
			continue
		}
		for _, p := range slices.SortedFunc(maps.Keys(r.routes), netip.Prefix.Compare) {
			if _, ok := want[p]; ok {
				continue
			}
			have := r.routes[p]
			if err := r.sys.delete(p, have.ifName); err != nil && !errors.Is(err, syscall.ESRCH) {
				r.logf("removing the route for %v from %s: %v", p, have.tunnel, err)
			}
			delete(r.routes, p)
		}
		return nil
	}
}

func (r *routeTable) point(p netip.Prefix, name string) error {
	ifName := r.claims[name].ifName
	have, ok := r.routes[p]
	var err error
	if ok {
		if err = r.sys.change(p, ifName); err == nil {
			r.logf("routing %v into %s instead of %s", p, name, have.tunnel)
		} else {
			r.logf("moving the route for %v from %s to %s: %v; replacing it", p, have.tunnel, name, err)
			r.sys.delete(p, have.ifName)
			delete(r.routes, p)
			err = r.sys.add(p, ifName)
		}
	} else {
		err = r.sys.add(p, ifName)
	}
	if err == nil {
		r.routes[p] = installedRoute{tunnel: name, ifName: ifName}
	}
	return err
}

var (
	unspecified4 = netip.MustParsePrefix("0.0.0.0/8")
	unspecified6 = netip.MustParsePrefix("::/8")
	nat64        = []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48")}
)

// kernelPrefixes leaves 0.0.0.0/8 and ::/8 (but NAT64) out of the routes, as
// the kernel looks up 0.0.0.0 or :: for the default route of the tunnels'
// interface-bound sockets, which fail if that's a tunnel's.
func kernelPrefixes(allowed []netip.Prefix) (routes, dropped []netip.Prefix) {
	add := func(p netip.Prefix) {
		if !slices.Contains(routes, p) {
			routes = append(routes, p)
		}
	}
	for _, p := range allowed {
		p = p.Masked()
		unspecified, keep := unspecified4, []netip.Prefix(nil)
		if p.Addr().Is6() {
			unspecified, keep = unspecified6, nat64
		}
		if !p.Contains(unspecified.Addr()) {
			add(p)
			continue
		}
		if p.Bits() >= unspecified.Bits() {
			dropped = append(dropped, p)
		}
		for bits := p.Bits() + 1; bits <= unspecified.Bits(); bits++ {
			b := unspecified.Addr().As16()
			if p.Addr().Is4() {
				b[12+(bits-1)/8] |= 0x80 >> ((bits - 1) % 8)
				add(netip.PrefixFrom(netip.AddrFrom16(b).Unmap(), bits))
			} else {
				b[(bits-1)/8] |= 0x80 >> ((bits - 1) % 8)
				add(netip.PrefixFrom(netip.AddrFrom16(b), bits))
			}
		}
		for _, q := range keep {
			if p.Overlaps(q) {
				add(q)
			}
		}
	}
	return routes, dropped
}
