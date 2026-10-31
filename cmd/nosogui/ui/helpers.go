//go:build gui

package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"

	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

func newFormDialog(title string, content fyne.CanvasObject, ok func(), w fyne.Window) dialog.Dialog {
	return dialog.NewCustomConfirm(title, "OK", "Cancel", content, func(b bool) {
		if b {
			ok()
		}
	}, w)
}

func gvtPrice(available int, sell bool) int64 { return storage.GVTPrice(available, sell) }

// walletHashes lists the wallet addresses in wallet order.
func walletHashes(n *node.Node) []string {
	var hs []string
	for _, w := range n.Wallet.All() {
		hs = append(hs, w.Hash)
	}
	return hs
}
