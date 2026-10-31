//go:build gui

// Command nosogui is the desktop front end of the node. It owns no business
// logic: every action goes through the same node, network and cli packages
// that nosod and nosocli use.
package main

import "github.com/pasichDev/noso-node-go/cmd/nosogui/ui"

func main() { ui.Run() }
