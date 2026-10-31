package ui

import (
	"fmt"
	"strings"
)

// mnSuffix marks a masternode funds address in the address grid.
const mnSuffix = " [MN]"

// addressFromRow returns the wallet address shown in a grid row, "" when the
// row does not exist. The grid has no header row, so row r is addrRows[r].
func addressFromRow(rows [][]string, row int) string {
	if row < 0 || row >= len(rows) || len(rows[row]) == 0 {
		return ""
	}
	return strings.TrimSuffix(rows[row][0], mnSuffix)
}

// sendStart returns the wallet index the send starts from: the position of
// the selected address in the wallet, 0 when nothing (valid) is selected.
// The row of a grid is not the wallet index: "hide empty" removes rows and
// the grid is rebuilt every second, so the selection is kept as an address
// and resolved against the wallet at the moment of sending. The original
// had the same bug (mpparser.pas:771 uses Row-1 on a filtered grid); the
// Go port also kept a "-1" for a header row that does not exist here, which
// started every send one address too early.
func sendStart(wallet []string, selected string) int {
	if selected == "" {
		return 0
	}
	for i, h := range wallet {
		if h == selected {
			return i
		}
	}
	return 0
}

// exportPath is where a wallet export goes: a new file in the chosen
// directory. It never names an existing file.
func exportPath(dir, stamp string, exists func(string) bool) string {
	base := strings.TrimRight(dir, "/\\") + "/noso-wallet-" + stamp
	p := base + ".pkw"
	for i := 2; exists(p) && i < 1000; i++ {
		p = fmt.Sprintf("%s-%d.pkw", base, i)
	}
	return p
}
