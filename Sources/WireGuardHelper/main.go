// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

// Command wireguard-helper runs the app's tunnels as root: it creates their
// interfaces, runs wireguard-go on them and sets up their routes and DNS.
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"wireguard-helper/internal/bind"
	"wireguard-helper/internal/tailscale/dns"
	"wireguard-helper/internal/tailscale/netmon"
	"wireguard-helper/internal/tailscale/netns"
)

const (
	version    = "3"
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

	ring := newRingLog()
	logger := log.New(ring, "", 0)
	logf := logger.Printf

	if err := dns.RemoveStale(logf); err != nil {
		logf("removing stale DNS configuration: %v", err)
	}
	bind.AddControl(netns.Control(logf))

	s := &server{logf: logf, log: ring, uid: *uid, requirement: *requirement, startTunnel: startTunnel, tunnels: map[string]*tunnel{}}
	if _, err := netmon.Watch(logf, s.networkChanged); err != nil {
		log.Fatalf("watching the network: %v", err)
	}
	log.Fatal(s.serve(socketPath))
}

type logEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

// ringLog writes to stderr and keeps the last entries for the app's log view.
type ringLog struct {
	id      int64 // tells this log apart from the one of another run of the helper
	mu      sync.Mutex
	entries []logEntry
	total   int
}

func newRingLog() *ringLog {
	return &ringLog{id: 1 + rand.Int64N(1<<53-1)} // Fits a JSON number.
}

func (r *ringLog) Write(p []byte) (int, error) {
	os.Stderr.Write(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, logEntry{time.Now().Format("2006-01-02 15:04:05.000"), strings.TrimSuffix(string(p), "\n")})
	r.total++
	if len(r.entries) > 2000 {
		r.entries = r.entries[len(r.entries)-2000:]
	}
	return len(p), nil
}

// since returns the entries written after the first cursor ones, and the new
// cursor. A cursor into another log, such as the one the app keeps while the
// helper restarts, counts as 0.
func (r *ringLog) since(id int64, cursor int) ([]logEntry, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != r.id || cursor > r.total {
		cursor = 0
	}
	first := r.total - len(r.entries)
	return append([]logEntry(nil), r.entries[max(cursor-first, 0):]...), r.total
}
