// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestRoutes(t *testing.T) {
	peers := []PeerConfig{
		{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}},
		{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.7/24")}},
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}
	if got := routes(peers); !reflect.DeepEqual(got, want) {
		t.Errorf("routes = %v, want %v", got, want)
	}
}

func TestUAPIConfig(t *testing.T) {
	cfg := Config{
		PrivateKey: "aa",
		ListenPort: 51820,
		Peers: []PeerConfig{
			{PublicKey: "bb", PresharedKey: "cc", PersistentKeepalive: 25, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			{PublicKey: "dd"},
		},
	}
	endpoints := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820"), {}}
	want := "private_key=aa\nlisten_port=51820\nreplace_peers=true\n" +
		"public_key=bb\npreshared_key=cc\nendpoint=192.0.2.1:51820\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=10.0.0.0/24\n" +
		"public_key=dd\npersistent_keepalive_interval=0\nreplace_allowed_ips=true\n"
	if got := uapiConfig(cfg, endpoints); got != want {
		t.Errorf("uapiConfig =\n%s\nwant\n%s", got, want)
	}
}

func TestResolveEndpoints(t *testing.T) {
	peers := []PeerConfig{{Endpoint: "192.0.2.1:51820"}, {Endpoint: "[2001:db8::1]:443"}, {}, {Endpoint: "localhost:51820"}}
	got, err := resolveEndpoints(peers, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != netip.MustParseAddrPort("192.0.2.1:51820") || got[1] != netip.MustParseAddrPort("[2001:db8::1]:443") || got[2].IsValid() {
		t.Errorf("literal endpoints = %v", got[:3])
	}
	if got[3] != netip.MustParseAddrPort("127.0.0.1:51820") {
		t.Errorf("localhost = %v, want 127.0.0.1:51820 (IPv4 preferred)", got[3])
	}

	previous := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.9:1")}
	kept, err := resolveEndpoints([]PeerConfig{{Endpoint: "nonexistent.invalid:1"}}, previous)
	if err != nil || kept[0] != previous[0] {
		t.Errorf("failed re-resolution = %v, %v; want the previous endpoint", kept, err)
	}
	if _, err := resolveEndpoints([]PeerConfig{{Endpoint: "nonexistent.invalid:1"}}, nil); err == nil {
		t.Error("failed initial resolution: no error")
	}
}

func TestRingLogSince(t *testing.T) {
	r := &ringLog{}
	for i := 0; i < 2005; i++ {
		r.Write([]byte("line\n"))
	}
	entries, cursor := r.since(0)
	if len(entries) != 2000 || cursor != 2005 {
		t.Fatalf("since(0) = %d entries, cursor %d; want 2000, 2005", len(entries), cursor)
	}
	r.Write([]byte("new\n"))
	entries, cursor = r.since(cursor)
	if len(entries) != 1 || entries[0].Message != "new" || cursor != 2006 {
		t.Fatalf("since(2005) = %v, cursor %d; want [new], 2006", entries, cursor)
	}
}
