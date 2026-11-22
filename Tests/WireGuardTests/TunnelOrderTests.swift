// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Testing
@testable import WireGuard

private func moved(_ list: [String], _ moves: [(from: Int, to: Int)]) -> [String] {
    var list = list
    for move in moves {
        list.insert(list.remove(at: move.from), at: move.to)
    }
    return list
}

private let list = ["a", "b", "c", "d", "e"]

@Test(arguments: [
    ([1, 4], 0, ["b", "e", "a", "c", "d"]), // dragged to the top
    ([0, 2], 5, ["b", "d", "e", "a", "c"]), // to the end
    ([0, 3], 2, ["b", "a", "d", "c", "e"]), // from above and below
    ([2], 2, list), // onto itself
    ([2], 3, list) // right below itself
])
func dragging(rows: [Int], to row: Int, result: [String]) {
    #expect(moved(list, TunnelsManager.moves(of: IndexSet(rows), to: row)) == result)
}

@Test(arguments: [
    ([1, 4], -1, ["b", "a", "c", "e", "d"]),
    ([0, 3], -1, ["a", "b", "d", "c", "e"]), // the top one stays
    ([0, 1], -1, list),
    ([3, 4], 1, list),
    ([1, 3], 1, ["a", "c", "b", "e", "d"])
])
func arrows(rows: [Int], offset: Int, result: [String]) {
    #expect(moved(list, TunnelsManager.moves(of: IndexSet(rows), by: offset, count: list.count)) == result)
}

@Test func listOrder() {
    let stored: [(name: String, position: Int?)] = [("old", nil), ("b", 1), ("Zed", nil), ("a", 0), ("c", 1)]
    #expect(stored.sorted(by: TunnelsManager.isInListOrder).map(\.name) == ["a", "b", "c", "old", "Zed"])
}
