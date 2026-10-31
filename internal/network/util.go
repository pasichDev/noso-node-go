package network

import (
	"net"
	"os"

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
			res += o.OrderID + "," + codec.IntToStr(o.TimeStamp) + "," + o.OrderType + "," + o.Address + "," +
				o.Receiver + "," + codec.IntToStr(o.AmmountTrf) + "," + codec.IntToStr(o.AmmountFee) + "," + o.Reference
		} else {
			res += o.OrderType + "," + o.Address + "," + o.Receiver + "," + codec.IntToStr(o.AmmountTrf) + "," +
				codec.IntToStr(o.AmmountFee)
		}
		res += " "
	}
	return res
}

func splitHostPort(a string) (string, string, error) { return net.SplitHostPort(a) }

func mustAtoi(s string) int { return int(codec.StrToIntDef(s, 0)) }
