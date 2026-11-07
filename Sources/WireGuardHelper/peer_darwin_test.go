// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The test binary is the peer: check it against its own designated requirement.
	executable, _ := os.Executable()
	out, err := exec.Command("codesign", "-d", "-r-", executable).CombinedOutput()
	_, designated, ok := strings.Cut(string(out), "designated => ")
	if err != nil || !ok {
		t.Fatalf("reading the designated requirement: %v\n%s", err, out)
	}
	uid, err := checkPeer(conn, strings.TrimSpace(designated))
	if err != nil {
		t.Errorf("own designated requirement: %v", err)
	}
	if uid != os.Geteuid() {
		t.Errorf("uid = %d, want %d", uid, os.Geteuid())
	}
	if _, err := checkPeer(conn, `cdhash H"0000000000000000000000000000000000000000"`); err == nil {
		t.Error("another cdhash: no error")
	}
	if _, err := checkPeer(conn, `identifier "dev.whyredfire.wireguard"`); err == nil {
		t.Error("another identifier: no error")
	}
}
