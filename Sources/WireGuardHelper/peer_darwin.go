// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

/*
#cgo LDFLAGS: -lbsm
#include <bsm/libbsm.h>
#include <sys/socket.h>
#include <sys/un.h>

#define CS_OPS_CDHASH 5
int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);

// Reads the effective user ID and code directory hash of the process at the
// other end of a Unix socket. The audit token, unlike a PID, can't be reused
// by another process.
static int peer_identity(int fd, uid_t *uid, unsigned char cdhash[20]) {
	audit_token_t token;
	socklen_t size = sizeof(token);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) != 0)
		return -1;
	*uid = audit_token_to_euid(token);
	return csops_audittoken(audit_token_to_pid(token), CS_OPS_CDHASH, cdhash, 20, &token);
}
*/
import "C"

import (
	"encoding/hex"
	"fmt"
	"net"
	"unsafe"
)

// peerIdentity returns the effective user ID and the hex encoded code
// directory hash of the process connected to conn.
func peerIdentity(conn *net.UnixConn) (uid int, cdhash string, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, "", err
	}
	var cUID C.uid_t
	var hash [20]byte
	var ret C.int
	if err := raw.Control(func(fd uintptr) {
		ret = C.peer_identity(C.int(fd), &cUID, (*C.uchar)(unsafe.Pointer(&hash[0])))
	}); err != nil {
		return 0, "", err
	}
	if ret != 0 {
		return 0, "", fmt.Errorf("reading the peer's identity failed")
	}
	return int(cUID), hex.EncodeToString(hash[:]), nil
}
