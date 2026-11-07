//go:build !linux
// +build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package bind

import "net"

func supportsUDPOffload(_ *net.UDPConn) (txOffload, rxOffload bool) {
	return
}
