// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"wireguard-helper/internal/tailscale/logger"
)

// Requests and responses are JSON objects, one per line.
type request struct {
	Op     string `json:"op"`
	Name   string `json:"name,omitempty"`
	Config Config `json:"config,omitempty"`
}

type response struct {
	Error     string   `json:"error,omitempty"`
	Version   string   `json:"version,omitempty"`
	Interface string   `json:"interface,omitempty"`
	Runtime   string   `json:"runtime,omitempty"`
	Log       []string `json:"log,omitempty"`
}

type server struct {
	logf    logger.Logf
	log     *ringLog
	uid     int
	cdhash  string
	mu      sync.Mutex
	tunnels map[string]*tunnel
}

func (s *server) serve(path string) error {
	os.Remove(path)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chown(path, s.uid, -1); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// handle serves one connection of the app. The tunnels it starts only live as
// long as the connection, so they stop when the app quits or crashes.
func (s *server) handle(conn *net.UnixConn) {
	defer conn.Close()
	uid, cdhash, err := peerIdentity(conn)
	if err != nil || uid != s.uid || (s.cdhash != "" && cdhash != s.cdhash) {
		s.logf("rejected a connection from uid %d, cdhash %s: %v", uid, cdhash, err)
		json.NewEncoder(conn).Encode(response{Error: "unauthorized"})
		return
	}

	started := map[string]bool{}
	defer func() {
		for name := range started {
			s.stop(name)
		}
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(nil, 1<<20)
	encoder := json.NewEncoder(conn)
	for scanner.Scan() {
		var req request
		var resp response
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			resp.Error = err.Error()
		} else if err := s.do(req, &resp, started); err != nil {
			resp.Error = err.Error()
		}
		if err := encoder.Encode(resp); err != nil {
			return
		}
	}
}

func (s *server) do(req request, resp *response, started map[string]bool) error {
	switch req.Op {
	case "version":
		resp.Version = version
	case "up":
		ifName, err := s.start(req.Config)
		if err != nil {
			return err
		}
		started[req.Config.Name] = true
		resp.Interface = ifName
	case "down":
		if !started[req.Name] {
			return fmt.Errorf("%s is not active", req.Name)
		}
		delete(started, req.Name)
		s.stop(req.Name)
	case "runtime":
		s.mu.Lock()
		t := s.tunnels[req.Name]
		s.mu.Unlock()
		if t == nil {
			return fmt.Errorf("%s is not active", req.Name)
		}
		config, err := t.dev.IpcGet()
		if err != nil {
			return err
		}
		resp.Runtime = config
	case "log":
		resp.Log = s.log.lines()
	default:
		return errors.New("unknown operation " + req.Op)
	}
	return nil
}

func (s *server) start(cfg Config) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnels[cfg.Name] != nil {
		return "", fmt.Errorf("%s is already active", cfg.Name)
	}
	t, err := startTunnel(s.logf, cfg)
	if err != nil {
		return "", err
	}
	s.tunnels[cfg.Name] = t
	return t.ifName, nil
}

func (s *server) stop(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.tunnels[name]; t != nil {
		t.stop()
		delete(s.tunnels, name)
	}
}

// networkChanged updates the tunnels without holding the lock, as resolving
// their endpoints can take a while.
func (s *server) networkChanged() {
	s.mu.Lock()
	tunnels := make([]*tunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		tunnels = append(tunnels, t)
	}
	s.mu.Unlock()
	for _, t := range tunnels {
		t.networkChanged()
	}
}
