// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package dns

import (
	"strings"

	"wireguard-helper/internal/tailscale/logger"
)

const (
	resolverDir        = "/etc/resolver"
	serviceIDPrefix    = "WireGuard-"
	resolverFileHeader = "# Added by WireGuard for "
)

// RemoveStale removes the DNS configuration of every tunnel, such as what a
// previous run left behind when it crashed.
func RemoveStale(logf logger.Logf) error {
	out, err := runScutil("list State:/Network/Service/" + serviceIDPrefix + "[^/]+/DNS\nquit\n")
	if err != nil {
		return err
	}
	var script strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if _, key, ok := strings.Cut(line, " = "); ok {
			script.WriteString("remove " + strings.TrimSpace(key) + "\n")
		}
	}
	if script.Len() > 0 {
		if _, err := runScutil(script.String() + "quit\n"); err != nil {
			return err
		}
	}
	c := &darwinConfigurator{logf: logf, resolverDir: resolverDir, header: resolverFileHeader}
	return c.removeResolverFiles(func(string) bool { return true })
}
