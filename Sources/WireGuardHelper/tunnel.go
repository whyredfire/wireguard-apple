// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"wireguard-helper/internal/bind"
	"wireguard-helper/internal/tailscale/dns"
	"wireguard-helper/internal/tailscale/logger"
	"wireguard-helper/internal/tailscale/router"
)

// Config is a tunnel's configuration as sent by the app. Keys are hex encoded.
type Config struct {
	Name       string         `json:"name"`
	PrivateKey string         `json:"privateKey"`
	ListenPort uint16         `json:"listenPort,omitempty"`
	MTU        int            `json:"mtu,omitempty"`
	Addresses  []netip.Prefix `json:"addresses"`
	DNS        []netip.Addr   `json:"dns,omitempty"`
	DNSSearch  []string       `json:"dnsSearch,omitempty"`
	SplitDNS   bool           `json:"splitDNS,omitempty"`
	Peers      []PeerConfig   `json:"peers"`
}

type PeerConfig struct {
	PublicKey           string         `json:"publicKey"`
	PresharedKey        string         `json:"presharedKey,omitempty"`
	Endpoint            string         `json:"endpoint,omitempty"`
	AllowedIPs          []netip.Prefix `json:"allowedIPs"`
	PersistentKeepalive uint16         `json:"persistentKeepalive,omitempty"`
}

type tunnel struct {
	cfg       Config
	logf      logger.Logf
	ifName    string
	dev       *device.Device
	router    interface{ Close() error }
	dns       interface{ Close() error }
	endpoints []netip.AddrPort
}

func startTunnel(logf logger.Logf, cfg Config) (t *tunnel, err error) {
	logf = prefixed(logf, cfg.Name)
	endpoints, err := resolveEndpoints(cfg.Peers, nil)
	if err != nil {
		return nil, err
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	tunDev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, fmt.Errorf("creating the tunnel interface: %w", err)
	}
	ifName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, err
	}
	t = &tunnel{cfg: cfg, logf: logf, ifName: ifName, endpoints: endpoints}
	t.dev = device.NewDevice(tunDev, bind.NewStdNetBind(), &device.Logger{Verbosef: logf, Errorf: logf})
	defer func() {
		if err != nil {
			t.stop()
		}
	}()

	if err := t.dev.IpcSet(uapiConfig(cfg, endpoints)); err != nil {
		return nil, fmt.Errorf("configuring wireguard-go: %w", err)
	}
	if err := t.dev.Up(); err != nil {
		return nil, err
	}

	r, err := router.New(logf, tunDev)
	if err != nil {
		return nil, err
	}
	t.router = r
	if err := r.Up(); err != nil {
		return nil, err
	}
	if err := r.Set(&router.Config{LocalAddrs: cfg.Addresses, Routes: routes(cfg.Peers)}); err != nil {
		return nil, fmt.Errorf("setting the routes: %w", err)
	}

	if len(cfg.DNS) > 0 {
		d := dns.NewOSConfigurator(logf, ifName)
		t.dns = d
		osCfg := dns.OSConfig{Nameservers: cfg.DNS, SearchDomains: cfg.DNSSearch}
		if cfg.SplitDNS {
			osCfg.MatchDomains = cfg.DNSSearch
		}
		if err := d.SetDNS(osCfg); err != nil {
			return nil, fmt.Errorf("setting DNS: %w", err)
		}
	}

	logf("started on %s", ifName)
	return t, nil
}

func (t *tunnel) stop() {
	if t.dns != nil {
		if err := t.dns.Close(); err != nil {
			t.logf("removing DNS: %v", err)
		}
	}
	// Closing the device destroys the interface, and with it its routes.
	t.dev.Close()
	if t.router != nil {
		t.router.Close()
	}
	t.logf("stopped")
}

// networkChanged rebinds the sockets to the new default interface and resets
// the peers' endpoints, re-resolving hostnames, as the old ones may only have
// been reachable from the previous network.
func (t *tunnel) networkChanged() {
	if err := t.dev.BindUpdate(); err != nil {
		t.logf("rebinding: %v", err)
	}
	t.endpoints, _ = resolveEndpoints(t.cfg.Peers, t.endpoints)
	var b strings.Builder
	for i, peer := range t.cfg.Peers {
		if t.endpoints[i].IsValid() {
			fmt.Fprintf(&b, "public_key=%s\nendpoint=%s\n", peer.PublicKey, t.endpoints[i])
		}
	}
	if err := t.dev.IpcSet(b.String()); err != nil {
		t.logf("resetting endpoints: %v", err)
	}
}

func uapiConfig(cfg Config, endpoints []netip.AddrPort) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKey)
	if cfg.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	for i, peer := range cfg.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", peer.PublicKey)
		if peer.PresharedKey != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", peer.PresharedKey)
		}
		if endpoints[i].IsValid() {
			fmt.Fprintf(&b, "endpoint=%s\n", endpoints[i])
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
	}
	return b.String()
}

// routes returns the routes into the tunnel for the peers' allowed IPs. A
// default route is split in two halves, which take precedence over the
// system's default route without replacing it.
func routes(peers []PeerConfig) []netip.Prefix {
	var routes []netip.Prefix
	for _, peer := range peers {
		for _, ip := range peer.AllowedIPs {
			switch ip.Masked() {
			case netip.MustParsePrefix("0.0.0.0/0"):
				routes = append(routes, netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"))
			case netip.MustParsePrefix("::/0"):
				routes = append(routes, netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"))
			default:
				routes = append(routes, ip.Masked())
			}
		}
	}
	return routes
}

// resolveEndpoints resolves the peers' endpoints, preferring IPv4 addresses.
// Without previous results, a failed resolution is an error; with them, the
// previous address is kept.
func resolveEndpoints(peers []PeerConfig, previous []netip.AddrPort) ([]netip.AddrPort, error) {
	endpoints := make([]netip.AddrPort, len(peers))
	for i, peer := range peers {
		if peer.Endpoint == "" {
			continue
		}
		endpoint, err := resolveEndpoint(peer.Endpoint)
		if err != nil {
			if previous == nil {
				return nil, fmt.Errorf("resolving %s: %w", peer.Endpoint, err)
			}
			endpoint = previous[i]
		}
		endpoints[i] = endpoint
	}
	return endpoints, nil
}

func resolveEndpoint(endpoint string) (netip.AddrPort, error) {
	if addrPort, err := netip.ParseAddrPort(endpoint); err == nil {
		return addrPort, nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	portNumber, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addr := addrs[0]
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() {
			addr = a.Unmap()
			break
		}
	}
	return netip.AddrPortFrom(addr, uint16(portNumber)), nil
}

func prefixed(logf logger.Logf, prefix string) logger.Logf {
	return func(format string, args ...any) {
		logf(prefix+": "+format, args...)
	}
}
