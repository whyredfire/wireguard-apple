// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

package bind

// AddControl adds fn to the functions applied to every socket the bind opens.
func AddControl(fn controlFn) {
	controlFns = append(controlFns, fn)
}
