package ui

import "testing"

func TestAddressFromRow(t *testing.T) {
	rows := [][]string{{"N1 [MN]", "1"}, {"N2", "0"}}
	if got := addressFromRow(rows, 0); got != "N1" {
		t.Fatalf("got %q", got)
	}
	if addressFromRow(rows, 2) != "" || addressFromRow(rows, -1) != "" || addressFromRow(nil, 0) != "" {
		t.Fatal("out of range row must give no address")
	}
}

// Finding 13: selecting the third address must start the send at the third
// address, not the second; with "hide empty" the row is not the wallet index.
func TestSendStart(t *testing.T) {
	wallet := []string{"A", "B", "C", "D"}
	// all rows visible: row 2 is wallet index 2 (the old code gave 1)
	rows := [][]string{{"A", ""}, {"B", ""}, {"C", ""}, {"D", ""}}
	if got := sendStart(wallet, addressFromRow(rows, 2)); got != 2 {
		t.Fatalf("start %d, want 2", got)
	}
	// B is empty and hidden: row 1 is C, wallet index 2
	hidden := [][]string{{"A", ""}, {"C", ""}, {"D", ""}}
	if got := sendStart(wallet, addressFromRow(hidden, 1)); got != 2 {
		t.Fatalf("hidden start %d, want 2", got)
	}
	if sendStart(wallet, "") != 0 || sendStart(wallet, "gone") != 0 {
		t.Fatal("no selection must start at the first address")
	}
}

func TestExportPathNeverNamesExistingFile(t *testing.T) {
	taken := map[string]bool{"/d/noso-wallet-1.pkw": true}
	p := exportPath("/d/", "1", func(s string) bool { return taken[s] })
	if taken[p] || p == "" {
		t.Fatalf("export path %q exists", p)
	}
}
