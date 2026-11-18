// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"wireguard-helper/internal/bind"
	"wireguard-helper/internal/tailscale/dns"
	"wireguard-helper/internal/tailscale/logger"
)

// testClient talks to a server whose tunnels are devices without an interface.
// The tunnel named "slow" only starts once release is closed, and "broken" never does.
type testClient struct {
	t         *testing.T
	server    *server
	conn      net.Conn
	responses *bufio.Scanner
	release   chan struct{}
	served    chan struct{}
	dns       *fakeDNS
}

type fakeDNS struct {
	mu     sync.Mutex
	orders map[string]int
	owners map[string]string
}

type fakeTunnelDNS struct {
	f    *fakeDNS
	name string
}

func (f *fakeDNS) forTunnel(name string) fakeTunnelDNS { return fakeTunnelDNS{f, name} }

func (d fakeTunnelDNS) SetDNS(cfg dns.OSConfig) error {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	if len(cfg.MatchDomains) == 0 {
		d.f.orders[d.name] = cfg.SearchOrder
	}
	for _, domain := range cfg.MatchDomains {
		d.f.owners[domain] = d.name
	}
	return nil
}

func (d fakeTunnelDNS) Close() error {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	delete(d.f.orders, d.name)
	maps.DeleteFunc(d.f.owners, func(_, owner string) bool { return owner == d.name })
	return nil
}

func (f *fakeDNS) owner(domain string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.owners[domain]
}

func (f *fakeDNS) snapshot() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.orders)
}

func newTestClient(t *testing.T) *testClient {
	c := &testClient{t: t, release: make(chan struct{}), served: make(chan struct{}), dns: &fakeDNS{orders: map[string]int{}, owners: map[string]string{}}}
	logf := func(string, ...any) {}
	c.server = &server{logf: logf, log: newRingLog(), routes: newRouteTable(logf, newFakeRoutes()), tunnels: map[string]*tunnel{}}
	c.server.startTunnel = func(_ logger.Logf, cfg Config) (*tunnel, error) {
		switch cfg.Name {
		case "slow":
			<-c.release
		case "broken":
			return nil, errors.New("broken")
		}
		dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), bind.NewStdNetBind(), &device.Logger{Verbosef: logf, Errorf: logf})
		t := &tunnel{cfg: cfg, logf: logf, ifName: "test-" + cfg.Name, dev: dev}
		if len(cfg.DNS) > 0 {
			t.dns = c.dns.forTunnel(cfg.Name)
			t.dnsConfig = dns.OSConfig{Nameservers: cfg.DNS}
			if cfg.SplitDNS {
				t.dnsConfig.MatchDomains = cfg.DNSSearch
			}
		}
		return t, nil
	}
	var serverConn net.Conn
	c.conn, serverConn = net.Pipe()
	c.responses = bufio.NewScanner(c.conn)
	go func() {
		c.server.serveClient(serverConn)
		close(c.served)
	}()
	t.Cleanup(func() { c.conn.Close() })
	return c
}

func (c *testClient) send(req request) {
	c.t.Helper()
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(c.conn).Encode(req); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testClient) receive() response {
	c.t.Helper()
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if !c.responses.Scan() {
		c.t.Fatalf("no response: %v", c.responses.Err())
	}
	var resp response
	if err := json.Unmarshal(c.responses.Bytes(), &resp); err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func (c *testClient) active() []string {
	c.server.mu.Lock()
	defer c.server.mu.Unlock()
	var names []string
	for name := range c.server.tunnels {
		names = append(names, name)
	}
	return names
}

func TestServeClient(t *testing.T) {
	c := newTestClient(t)

	c.send(request{ID: 1, Op: "version"})
	if resp := c.receive(); resp.ID != 1 || resp.Version != version {
		t.Errorf("version = %+v", resp)
	}
	c.send(request{ID: 2, Op: "down", Name: "fast"})
	if resp := c.receive(); resp.ID != 2 || resp.Error == "" {
		t.Errorf("down of an inactive tunnel = %+v, want an error", resp)
	}
	c.send(request{ID: 3, Op: "nonsense"})
	if resp := c.receive(); resp.ID != 3 || resp.Error == "" {
		t.Errorf("unknown operation = %+v, want an error", resp)
	}
	c.send(request{ID: 4, Op: "up", Config: Config{Name: "broken"}})
	if resp := c.receive(); resp.ID != 4 || resp.Error != "broken" {
		t.Errorf("up of a tunnel that doesn't start = %+v", resp)
	}
	if active := c.active(); len(active) != 0 {
		t.Errorf("active after a failed start = %v", active)
	}

	// A stale cursor, as kept by the app across a restart of the helper.
	c.server.log.Write([]byte("one\n"))
	c.send(request{ID: 5, Op: "log", LogID: c.server.log.id + 1, Cursor: 150})
	if resp := c.receive(); resp.ID != 5 || resp.Error != "" || len(resp.Log) != 1 || resp.Cursor != 1 || resp.LogID != c.server.log.id {
		t.Errorf("log with a stale cursor = %+v", resp)
	}
	c.send(request{ID: 6, Op: "log", LogID: c.server.log.id, Cursor: 1})
	if resp := c.receive(); resp.ID != 6 || len(resp.Log) != 0 || resp.Cursor != 1 {
		t.Errorf("log with the current cursor = %+v", resp)
	}
}

func TestServeClientDNSOrder(t *testing.T) {
	c := newTestClient(t)
	servers := []netip.Addr{netip.MustParseAddr("192.0.2.53")}
	c.send(request{ID: 1, Op: "order", Names: []string{"top", "fast", "other"}})
	c.receive()
	for id, name := range []string{"fast", "other"} {
		c.send(request{ID: 2 + id, Op: "up", Config: Config{Name: name, DNS: servers}})
		if resp := c.receive(); resp.Error != "" {
			t.Fatalf("up %s = %+v", name, resp)
		}
	}
	if got, want := c.dns.snapshot(), map[string]int{"fast": 100001, "other": 100002}; !maps.Equal(got, want) {
		t.Errorf("DNS orders = %v, want %v", got, want)
	}
	c.send(request{ID: 4, Op: "order", Names: []string{"other", "fast"}})
	c.receive()
	if got, want := c.dns.snapshot(), map[string]int{"fast": 100001, "other": 100000}; !maps.Equal(got, want) {
		t.Errorf("DNS orders after reordering = %v, want %v", got, want)
	}
	c.send(request{ID: 5, Op: "down", Name: "other"})
	c.receive()
	c.send(request{ID: 6, Op: "order", Names: []string{"fast", "other"}})
	c.receive()
	if got, want := c.dns.snapshot(), map[string]int{"fast": 100000}; !maps.Equal(got, want) {
		t.Errorf("DNS orders after stopping one = %v, want %v", got, want)
	}
}

func TestServeClientSplitDNSOrder(t *testing.T) {
	c := newTestClient(t)
	cfg := func(name string) Config {
		return Config{Name: name, DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, DNSSearch: []string{"corp.example"}, SplitDNS: true}
	}
	c.send(request{ID: 1, Op: "order", Names: []string{"fast", "other"}})
	c.receive()
	c.send(request{ID: 2, Op: "up", Config: cfg("fast")})
	c.receive()
	c.send(request{ID: 3, Op: "up", Config: cfg("other")})
	c.receive()
	if got := c.dns.owner("corp.example"); got != "fast" {
		t.Errorf("owner after the lower tunnel started = %q, want fast", got)
	}
	c.send(request{ID: 4, Op: "order", Names: []string{"other", "fast"}})
	c.receive()
	if got := c.dns.owner("corp.example"); got != "other" {
		t.Errorf("owner after reordering = %q, want other", got)
	}
	c.send(request{ID: 5, Op: "down", Name: "other"})
	c.receive()
	if got := c.dns.owner("corp.example"); got != "fast" {
		t.Errorf("owner after the first tunnel stopped = %q, want fast", got)
	}
}

func TestServeClientRoutes(t *testing.T) {
	c := newTestClient(t)
	f := c.server.routes.sys.(*fakeRoutes)
	peers := []PeerConfig{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}}
	lan := netip.MustParsePrefix("10.0.0.0/24")

	c.send(request{ID: 1, Op: "order", Names: []string{"fast", "other"}})
	c.receive()
	for id, name := range []string{"other", "fast"} {
		c.send(request{ID: 2 + id, Op: "up", Config: Config{Name: name, Peers: peers}})
		if resp := c.receive(); resp.Error != "" {
			t.Fatalf("up %s = %+v", name, resp)
		}
	}
	checkKernel(t, f, map[netip.Prefix]string{lan: "test-fast"})

	c.send(request{ID: 4, Op: "order", Names: []string{"other", "fast"}})
	c.receive()
	checkKernel(t, f, map[netip.Prefix]string{lan: "test-other"})

	c.send(request{ID: 5, Op: "down", Name: "other"})
	c.receive()
	checkKernel(t, f, map[netip.Prefix]string{lan: "test-fast"})

	c.conn.Close()
	<-c.served
	checkKernel(t, f, map[netip.Prefix]string{})
}

// A tunnel that takes long to start must not hold up requests about other
// tunnels, while requests about itself wait for their turn.
func TestServeClientSlowStart(t *testing.T) {
	c := newTestClient(t)

	c.send(request{ID: 1, Op: "up", Config: Config{Name: "slow"}})
	c.send(request{ID: 2, Op: "down", Name: "slow"})
	c.send(request{ID: 3, Op: "up", Config: Config{Name: "slow"}})
	c.send(request{ID: 4, Op: "up", Config: Config{Name: "fast"}})
	if resp := c.receive(); resp.ID != 4 || resp.Interface != "test-fast" {
		t.Fatalf("up of another tunnel during a slow start = %+v", resp)
	}
	c.send(request{ID: 5, Op: "runtime", Name: "fast"})
	if resp := c.receive(); resp.ID != 5 || resp.Error != "" {
		t.Fatalf("runtime of another tunnel during a slow start = %+v", resp)
	}
	c.send(request{ID: 6, Op: "down", Name: "fast"})
	if resp := c.receive(); resp.ID != 6 || resp.Error != "" {
		t.Fatalf("down of another tunnel during a slow start = %+v", resp)
	}

	close(c.release)
	for id := 1; id <= 3; id++ {
		if resp := c.receive(); resp.ID != id || resp.Error != "" {
			t.Fatalf("response %d about the slow tunnel = %+v", id, resp)
		}
	}
	if active := c.active(); len(active) != 1 || active[0] != "slow" {
		t.Errorf("active = %v, want [slow]", active)
	}

	// The tunnels stop with the connection.
	c.conn.Close()
	<-c.served
	if active := c.active(); len(active) != 0 {
		t.Errorf("active after disconnecting = %v", active)
	}
}
