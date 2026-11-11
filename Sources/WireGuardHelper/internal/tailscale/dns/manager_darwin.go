// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"wireguard-helper/internal/tailscale/logger"
)

// OSConfig is the subset of Tailscale's OSConfig that applies here.
type OSConfig struct {
	Nameservers   []netip.Addr
	SearchDomains []string
	MatchDomains  []string
}

// NewOSConfigurator creates a new OS configurator for the tunnel on ifName.
// Each tunnel keeps its own dynamic-store key and resolver files.
func NewOSConfigurator(logf logger.Logf, ifName string) *darwinConfigurator {
	return &darwinConfigurator{
		logf:         logf,
		ifName:       ifName,
		resolverDir:  resolverDir,
		runScutil:    runScutil,
		globalDNSKey: "State:/Network/Service/" + serviceIDPrefix + ifName + "/DNS",
		header:       resolverFileHeader + ifName + "\n",
		searchFile:   "search.wireguard-" + ifName,
	}
}

// darwinConfigurator is the tailscaled-on-macOS DNS OS configurator that
// maintains the Split DNS nameserver entries pointing MagicDNS DNS suffixes
// to 100.100.100.100 using the macOS /etc/resolver/$SUFFIX files.
type darwinConfigurator struct {
	logf         logger.Logf
	ifName       string
	resolverDir  string // default "/etc/resolver"
	runScutil    func(script string) (output string, err error)
	globalDNSKey string
	header       string
	searchFile   string
}

func (c *darwinConfigurator) Close() error {
	if err := c.removeGlobalDNS(); err != nil {
		return err
	}
	return c.removeResolverFiles(func(domain string) bool { return true })
}

func (c *darwinConfigurator) SupportsSplitDNS() bool {
	return true
}

func (c *darwinConfigurator) SetDNS(cfg OSConfig) error {
	if len(cfg.Nameservers) > 0 && len(cfg.MatchDomains) == 0 {
		if err := c.setGlobalDNS(cfg); err != nil {
			return err
		}
		return c.removeResolverFiles(func(domain string) bool { return true })
	}
	if err := c.removeGlobalDNS(); err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.WriteString(c.header)
	for _, ip := range cfg.Nameservers {
		buf.WriteString("nameserver ")
		buf.WriteString(ip.String())
		buf.WriteString("\n")
	}

	if err := os.MkdirAll(c.resolverDir, 0755); err != nil {
		return err
	}

	root, err := os.OpenRoot(c.resolverDir)
	if err != nil {
		return err
	}
	defer root.Close()

	keep := map[string]bool{}

	// Add a dummy file to /etc/resolver with a "search ..." directive if we have
	// search suffixes to add.
	if len(cfg.SearchDomains) > 0 {
		searchFile := c.searchFile // fake DNS suffix+TLD to put our search
		keep[searchFile] = true
		var sbuf bytes.Buffer
		sbuf.WriteString(c.header)
		sbuf.WriteString("search")
		for _, d := range cfg.SearchDomains {
			sbuf.WriteString(" ")
			sbuf.WriteString(strings.TrimSuffix(d, "."))
		}
		sbuf.WriteString("\n")
		if err := root.WriteFile(searchFile, sbuf.Bytes(), 0644); err != nil {
			return err
		}
	}

	for _, d := range cfg.MatchDomains {
		fileBase := strings.TrimSuffix(d, ".")
		keep[fileBase] = true

		if !isValidResolverFileName(fileBase) {
			c.logf("[unexpected] invalid resolver domain %q with slashes or colons", fileBase)
			return fmt.Errorf("invalid resolver domain %q: must not contain slashes or colons", fileBase)
		}

		// Closing removes the file, so leave alone one that something else put there.
		if existing, err := root.ReadFile(fileBase); err == nil && !bytes.HasPrefix(existing, []byte(resolverFileHeader)) {
			return fmt.Errorf("%s already has a resolver file that isn't WireGuard's", fileBase)
		}

		if err := root.WriteFile(fileBase, buf.Bytes(), 0644); err != nil {
			return err
		}
	}
	return c.removeResolverFiles(func(domain string) bool { return !keep[domain] })
}

// setGlobalDNS installs cfg.Nameservers as a default resolver using
// SystemConfiguration's dynamic store. /etc/resolver is only a split-DNS
// mechanism; it cannot express a primary resolver.
func (c *darwinConfigurator) setGlobalDNS(cfg OSConfig) error {
	var script strings.Builder
	script.WriteString("d.init\n")
	script.WriteString("d.add SearchOrder # 100000\n")
	script.WriteString("d.add ServerAddresses *")
	for _, ip := range cfg.Nameservers {
		script.WriteByte(' ')
		script.WriteString(ip.String())
	}
	script.WriteByte('\n')
	// An empty SupplementalMatchDomains entry makes this a default resolver.
	script.WriteString("d.add SupplementalMatchDomains * \"\"\n")
	if len(cfg.SearchDomains) > 0 {
		script.WriteString("d.add SearchDomains *")
		for _, fqdn := range cfg.SearchDomains {
			script.WriteByte(' ')
			writeScutilString(&script, strings.TrimSuffix(fqdn, "."))
		}
		script.WriteByte('\n')
	}
	script.WriteString("set ")
	script.WriteString(c.globalDNSKey)
	script.WriteString("\nquit\n")

	out, err := c.runScutilScript(script.String())
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out != "" {
		return fmt.Errorf("scutil set %s: %s", c.globalDNSKey, out)
	}
	return nil
}

func (c *darwinConfigurator) removeGlobalDNS() error {
	script := "remove " + c.globalDNSKey + "\nquit\n"
	out, err := c.runScutilScript(script)
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "No such key" {
		return nil
	}
	return fmt.Errorf("scutil remove %s: %s", c.globalDNSKey, out)
}

func (c *darwinConfigurator) runScutilScript(script string) (string, error) {
	run := c.runScutil
	if run == nil {
		run = runScutil
	}
	return run(script)
}

func runScutil(script string) (string, error) {
	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func writeScutilString(b *strings.Builder, v string) {
	if v == "" || strings.ContainsAny(v, " \t\n\"") {
		b.WriteString(strconv.Quote(v))
		return
	}
	b.WriteString(v)
}

func isValidResolverFileName(name string) bool {
	// Verify that the filename doesn't contain any characters that
	// might cause issues when used as a filename; os.Root is a
	// defense against path traversal, but prefer a nice error here
	// if we can. These aren't valid for domain names anyway.
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}

	if strings.Contains(name, ":") {
		return false
	}
	return true
}

// removeResolverFiles deletes all files in /etc/resolver for which the shouldDelete
// func returns true.
func (c *darwinConfigurator) removeResolverFiles(shouldDelete func(domain string) bool) error {
	root, err := os.OpenRoot(c.resolverDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()

	dents, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	for _, de := range dents {
		if !de.Type().IsRegular() {
			continue
		}
		name := de.Name()
		if !shouldDelete(name) {
			continue
		}
		contents, err := root.ReadFile(name)
		if err != nil {
			if os.IsNotExist(err) { // race?
				continue
			}
			return err
		}
		if !bytes.HasPrefix(contents, []byte(c.header)) {
			continue
		}
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	return nil
}
