// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"net"
	"net/netip"
	"os"
	"sync/atomic"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// kernelRoutes writes to a routing socket, as route(8) exits with 0 even when
// the kernel refuses a change.
type kernelRoutes struct{}

var routeSeq atomic.Int32

func (kernelRoutes) add(p netip.Prefix, ifName string) error {
	return writeRoute(unix.RTM_ADD, p, ifName)
}

func (kernelRoutes) change(p netip.Prefix, ifName string) error {
	return writeRoute(unix.RTM_CHANGE, p, ifName)
}

func (kernelRoutes) delete(p netip.Prefix, ifName string) error {
	return writeRoute(unix.RTM_DELETE, p, ifName)
}

func writeRoute(typ int, p netip.Prefix, ifName string) error {
	// shortcut: ~50µs interface lookup per route, so ~0.5s for 10,000 allowed IPs; look it up once per tunnel if lists that long matter.
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}
	link := &route.LinkAddr{Index: iface.Index, Name: ifName}
	addrs := []route.Addr{unix.RTAX_DST: inetAddr(p.Addr()), unix.RTAX_GATEWAY: link, unix.RTAX_NETMASK: inetMask(p)}
	if typ == unix.RTM_CHANGE {
		addrs = append(addrs, make([]route.Addr, unix.RTAX_IFP+1-len(addrs))...)
		addrs[unix.RTAX_IFP] = link
	}
	msg := route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    typ,
		Flags:   unix.RTF_UP | unix.RTF_STATIC,
		ID:      uintptr(os.Getpid()),
		Seq:     int(routeSeq.Add(1)),
		Addrs:   addrs,
	}
	b, err := msg.Marshal()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.Shutdown(fd, unix.SHUT_RD)
	_, err = unix.Write(fd, b)
	return err
}

func inetAddr(addr netip.Addr) route.Addr {
	if addr.Is4() {
		return &route.Inet4Addr{IP: addr.As4()}
	}
	return &route.Inet6Addr{IP: addr.As16()}
}

func inetMask(p netip.Prefix) route.Addr {
	bits := p.Addr().BitLen()
	mask := net.CIDRMask(p.Bits(), bits)
	addr, _ := netip.AddrFromSlice(mask)
	return inetAddr(addr)
}
