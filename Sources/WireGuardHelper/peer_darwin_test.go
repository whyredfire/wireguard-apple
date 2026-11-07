// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPeerIdentity(t *testing.T) {
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

	uid, cdhash, err := peerIdentity(conn)
	if err != nil {
		t.Fatal(err)
	}
	if uid != os.Geteuid() {
		t.Errorf("uid = %d, want %d", uid, os.Geteuid())
	}
	executable, _ := os.Executable()
	out, _ := exec.Command("codesign", "-dvvv", executable).CombinedOutput()
	want := regexp.MustCompile(`CDHash=([0-9a-f]+)`).FindStringSubmatch(string(out))
	if want == nil {
		t.Fatalf("no CDHash in codesign output:\n%s", out)
	}
	if !strings.EqualFold(cdhash, want[1]) {
		t.Errorf("cdhash = %s, want %s", cdhash, want[1])
	}
}
