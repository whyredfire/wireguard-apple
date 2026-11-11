// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"wireguard-helper/internal/tailscale/logger"
)

// Requests and responses are JSON objects, one per line. A response carries
// the ID of its request, as the responses to requests about different tunnels
// can come in another order than the requests.
type request struct {
	ID     int    `json:"id"`
	Op     string `json:"op"`
	Name   string `json:"name,omitempty"`
	Config Config `json:"config,omitempty"`
	Cursor int    `json:"cursor,omitempty"`
	LogID  int64  `json:"logID,omitempty"`
}

type response struct {
	ID        int        `json:"id,omitempty"`
	Error     string     `json:"error,omitempty"`
	Version   string     `json:"version,omitempty"`
	Interface string     `json:"interface,omitempty"`
	Runtime   string     `json:"runtime,omitempty"`
	Log       []logEntry `json:"log,omitempty"`
	Cursor    int        `json:"cursor,omitempty"`
	LogID     int64      `json:"logID,omitempty"`
}

type server struct {
	logf        logger.Logf
	log         *ringLog
	uid         int
	requirement string
	startTunnel func(logger.Logf, Config) (*tunnel, error)
	mu          sync.Mutex
	tunnels     map[string]*tunnel // nil while a tunnel is starting
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

func (s *server) handle(conn *net.UnixConn) {
	defer conn.Close()
	uid, err := checkPeer(conn, s.requirement)
	if err != nil || uid != s.uid {
		s.logf("rejected a connection from uid %d: %v", uid, err)
		json.NewEncoder(conn).Encode(response{Error: "unauthorized"})
		return
	}
	s.serveClient(conn)
}

// serveClient serves one connection of the app. The tunnels it starts only
// live as long as the connection, so they stop when the app quits or crashes.
//
// Requests about the same tunnel are handled in the order they came in, and
// those about different tunnels at the same time, so that a tunnel that takes
// long to start doesn't hold up the others.
func (s *server) serveClient(conn io.ReadWriter) {
	var started sync.Map // the names of the tunnels started over this connection
	var requests sync.WaitGroup
	defer func() {
		requests.Wait()
		started.Range(func(name, _ any) bool {
			s.stop(name.(string))
			return true
		})
	}()

	var writing sync.Mutex
	encoder := json.NewEncoder(conn)
	latest := map[string]chan struct{}{} // by tunnel, closed when its latest request is done
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(nil, 1<<20)
	for scanner.Scan() {
		var req request
		err := json.Unmarshal(scanner.Bytes(), &req)
		name := req.Name
		if req.Op == "up" {
			name = req.Config.Name
		}
		previous, done := latest[name], make(chan struct{})
		latest[name] = done
		requests.Go(func() {
			defer close(done)
			if previous != nil {
				<-previous
			}
			resp := response{ID: req.ID}
			if err == nil {
				err = s.do(req, &resp, &started)
			}
			if err != nil {
				resp.Error = err.Error()
			}
			writing.Lock()
			defer writing.Unlock()
			encoder.Encode(resp)
		})
	}
}

func (s *server) do(req request, resp *response, started *sync.Map) error {
	switch req.Op {
	case "version":
		resp.Version = version
	case "up":
		ifName, err := s.start(req.Config)
		if err != nil {
			return err
		}
		started.Store(req.Config.Name, true)
		resp.Interface = ifName
	case "down":
		if _, ok := started.LoadAndDelete(req.Name); !ok {
			return fmt.Errorf("%s is not active", req.Name)
		}
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
		resp.Log, resp.Cursor = s.log.since(req.LogID, req.Cursor)
		resp.LogID = s.log.id
	default:
		return errors.New("unknown operation " + req.Op)
	}
	return nil
}

// start starts a tunnel without holding the lock, as resolving its endpoints
// can take a while. Its name is taken in the meantime.
func (s *server) start(cfg Config) (string, error) {
	s.mu.Lock()
	if _, ok := s.tunnels[cfg.Name]; ok {
		s.mu.Unlock()
		return "", fmt.Errorf("%s is already active", cfg.Name)
	}
	s.tunnels[cfg.Name] = nil
	s.mu.Unlock()

	t, err := s.startTunnel(s.logf, cfg)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		delete(s.tunnels, cfg.Name)
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
		if t != nil {
			tunnels = append(tunnels, t)
		}
	}
	s.mu.Unlock()
	for _, t := range tunnels {
		t.networkChanged()
	}
}
