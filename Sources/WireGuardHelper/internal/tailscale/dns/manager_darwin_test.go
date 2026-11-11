// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package dns

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitDNSKeepsForeignResolverFiles(t *testing.T) {
	dir := t.TempDir()
	c := NewOSConfigurator(func(string, ...any) {}, "utun9")
	c.resolverDir = dir
	c.runScutil = func(string) (string, error) { return "", nil }

	foreign := filepath.Join(dir, "corp.example.com")
	if err := os.WriteFile(foreign, []byte("nameserver 192.0.2.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, MatchDomains: []string{"corp.example.com"}}
	if err := c.SetDNS(cfg); err == nil {
		t.Error("SetDNS over another tool's resolver file: no error")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(foreign); string(got) != "nameserver 192.0.2.53\n" {
		t.Errorf("another tool's resolver file = %q, want it untouched", got)
	}

	// Its own files, and those of another tunnel, are replaced and removed.
	cfg.MatchDomains = []string{"internal.example.com"}
	other := NewOSConfigurator(c.logf, "utun8")
	other.resolverDir, other.runScutil = dir, c.runScutil
	if err := other.SetDNS(cfg); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.SetDNS(cfg); err != nil {
			t.Fatal(err)
		}
	}
	own := filepath.Join(dir, "internal.example.com")
	if got, _ := os.ReadFile(own); string(got) != "# Added by WireGuard for utun9\nnameserver 10.0.0.1\n" {
		t.Errorf("resolver file = %q", got)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Errorf("resolver file after closing: %v, want it removed", err)
	}
}
