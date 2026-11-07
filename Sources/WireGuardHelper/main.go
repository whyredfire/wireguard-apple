// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

// Command wireguard-helper runs the app's tunnels as root: it creates their
// interfaces, runs wireguard-go on them and sets up their routes and DNS.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"wireguard-helper/internal/bind"
	"wireguard-helper/internal/tailscale/dns"
	"wireguard-helper/internal/tailscale/netmon"
	"wireguard-helper/internal/tailscale/netns"
)

const (
	version    = "1"
	socketPath = "/var/run/dev.whyredfire.wireguard.helper.sock"
)

func main() {
	uid := flag.Int("uid", -1, "the user allowed to connect")
	requirement := flag.String("requirement", "", "the code requirement of the app allowed to connect")
	flag.Parse()
	if *uid < 0 || *requirement == "" {
		fmt.Fprintln(os.Stderr, "usage: wireguard-helper -uid <uid> -requirement <code requirement>")
		os.Exit(64)
	}

	ring := &ringLog{}
	logger := log.New(ring, "", log.LstdFlags)
	logf := logger.Printf

	if err := dns.RemoveStale(logf); err != nil {
		logf("removing stale DNS configuration: %v", err)
	}
	bind.AddControl(netns.Control(logf))

	s := &server{logf: logf, log: ring, uid: *uid, requirement: *requirement, tunnels: map[string]*tunnel{}}
	if _, err := netmon.Watch(logf, s.networkChanged); err != nil {
		log.Fatalf("watching the network: %v", err)
	}
	log.Fatal(s.serve(socketPath))
}

// ringLog writes to stderr and keeps the last lines for the app's log view.
type ringLog struct {
	mu  sync.Mutex
	buf []string
}

func (r *ringLog) Write(p []byte) (int, error) {
	os.Stderr.Write(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, string(p))
	if len(r.buf) > 2000 {
		r.buf = r.buf[len(r.buf)-2000:]
	}
	return len(p), nil
}

func (r *ringLog) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.buf...)
}
