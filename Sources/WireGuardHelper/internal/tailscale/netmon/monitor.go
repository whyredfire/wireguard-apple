// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package netmon

import (
	"io"
	"time"

	"wireguard-helper/internal/tailscale/logger"
)

type message interface{ ignore() bool }

type osMon interface {
	io.Closer
	Receive() (message, error)
}

// Watch calls onChange when the routing table or an interface changes,
// debounced by a second like Tailscale's Monitor, until the returned Closer is closed.
func Watch(logf logger.Logf, onChange func()) (io.Closer, error) {
	mon, err := newOSMon(logf)
	if err != nil {
		return nil, err
	}
	changes := make(chan struct{}, 1)
	go func() {
		defer close(changes)
		for {
			msg, err := mon.Receive()
			if err != nil {
				return
			}
			if !msg.ignore() {
				select {
				case changes <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
		for range changes {
			time.Sleep(time.Second)
			select {
			case <-changes:
			default:
			}
			onChange()
		}
	}()
	return mon, nil
}
