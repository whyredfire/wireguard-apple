// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package logger defines a type for writing to logs.
package logger

// Logf is the basic Tailscale logger type: a printf-like func.
type Logf func(format string, args ...any)
