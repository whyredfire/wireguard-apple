// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package main

/*
#cgo LDFLAGS: -lbsm -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <sys/socket.h>
#include <sys/un.h>

// Checks the process at the other end of a Unix socket against a code
// requirement, identifying it by its audit token, which unlike a PID can't be
// reused by another process.
static OSStatus check_peer(int fd, const char *requirement_text, uid_t *uid) {
	audit_token_t token;
	socklen_t size = sizeof(token);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) != 0)
		return errSecIO;
	*uid = audit_token_to_euid(token);

	CFDataRef token_data = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *values[] = { token_data };
	CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecCodeRef code = NULL;
	OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
	CFRelease(attributes);
	CFRelease(token_data);
	if (status != errSecSuccess)
		return status;

	CFStringRef text = CFStringCreateWithCString(NULL, requirement_text, kCFStringEncodingUTF8);
	SecRequirementRef requirement = NULL;
	status = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
	CFRelease(text);
	if (status == errSecSuccess) {
		status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
		CFRelease(requirement);
	}
	CFRelease(code);
	return status;
}
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"
)

// checkPeer returns the effective user ID of the process connected to conn,
// and an error unless its code satisfies the code requirement.
func checkPeer(conn *net.UnixConn, requirement string) (uid int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	text := C.CString(requirement)
	defer C.free(unsafe.Pointer(text))
	var cUID C.uid_t = C.uid_t(^uint32(0))
	var status C.OSStatus
	if err := raw.Control(func(fd uintptr) {
		status = C.check_peer(C.int(fd), text, &cUID)
	}); err != nil {
		return -1, err
	}
	if status != C.errSecSuccess {
		return int(cUID), fmt.Errorf("code requirement not satisfied (OSStatus %d)", int(status))
	}
	return int(cUID), nil
}
