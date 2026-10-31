package node

import (
	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// SendFundsFromAddress mirrors mpcoin.pas:272-303. The origin must be a
// wallet address (the wallet lookup also matches aliases). COMPAT: TrfrID is
// hashed with the REQUESTED amount (monto), not the capped one, while the
// signature covers the capped amount.
func (n *Node) SendFundsFromAddress(origen, destino string, monto, comision int64, reference, orderTime string, line int) (types.Order, error) {
	idx := n.Wallet.IndexOf(origen)
	w := n.Wallet.At(idx)
	available := n.Summary.BalanceIndexed(w.Hash) - n.AddressPendingPays(origen)
	var fee int64
	if available > comision {
		fee = comision
	} else {
		fee = available
	}
	var trf int64
	if available > monto+comision {
		trf = monto
	} else {
		trf = available - comision
	}
	if trf < 0 {
		trf = 0
	}
	ts, ok := codec.StrToInt64(orderTime)
	if !ok {
		return types.Order{}, errBadTime
	}
	o := types.Order{
		OrderLines: 1, OrderType: "TRFR", TimeStamp: ts, Reference: reference,
		TrxLine: int32(line), Sender: w.PublicKey, Address: w.Hash, Receiver: destino,
		AmmountFee: fee, AmmountTrf: trf,
		Signature: crypto.GetStringSigned(orderTime+origen+destino+codec.IntToStr(trf)+
			codec.IntToStr(fee)+codec.IntToStr(int64(line)), w.PrivateKey),
		TrfrID: crypto.GetTransferHash(orderTime + origen + destino + codec.IntToStr(monto) +
			codec.IntToStr(n.MyLastBlock())),
	}
	o.Normalize()
	return o, nil
}

type nodeError string

func (e nodeError) Error() string { return string(e) }

const errBadTime = nodeError("invalid order time")
