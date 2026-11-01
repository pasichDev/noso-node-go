package network

import (
	"net"
	"os"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

func stringFromOrder(o types.Order) string { return types.StringFromOrder(o) }

// PendingRawInfo mirrors mpcoin.pas:417-456: comma separated fields,
// orders separated by blanks. forRPC adds the order id, timestamp and
// reference. COMPAT: the Pascal `Trim(result)` discards its value, so the
// answer keeps a trailing blank.
func PendingRawInfo(n *node.Node, forRPC bool) string {
	res := ""
	for _, o := range n.PendingCopy() {
		if forRPC {
			// FIX(F-10): a signed CUSTOM order carries a free-text reference; a
			// separator in it would start a fake entry of its own.
			res += cleanField(o.OrderID) + "," + codec.IntToStr(o.TimeStamp) + "," + cleanField(o.OrderType) + "," +
				cleanField(o.Address) + "," + cleanField(o.Receiver) + "," + codec.IntToStr(o.AmmountTrf) + "," +
				codec.IntToStr(o.AmmountFee) + "," + cleanField(o.Reference)
		} else {
			res += o.OrderType + "," + o.Address + "," + o.Receiver + "," + codec.IntToStr(o.AmmountTrf) + "," +
				codec.IntToStr(o.AmmountFee)
		}
		res += " "
	}
	return res
}

// cleanField makes a free-text field safe inside a comma and blank separated
// list: separators and control characters become '_'.
func cleanField(v string) string {
	return strings.Map(func(r rune) rune {
		if r == ',' || r == ' ' || r == 0x7f || r < 0x20 {
			return '_'
		}
		return r
	}, v)
}

func splitHostPort(a string) (string, string, error) { return net.SplitHostPort(a) }

func mustAtoi(s string) int { return int(codec.StrToIntDef(s, 0)) }
