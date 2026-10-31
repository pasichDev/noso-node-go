package rpc

import (
	"errors"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
)

var errConv = errors.New("rpc: conversion error")

func strToBool(s string) (bool, error) {
	switch codec.ASCIIUpper(s) {
	case "TRUE", "-1":
		return true, nil
	case "FALSE", "0":
		return false, nil
	}
	return false, errConv
}

// ObjectFromString mirrors ObjectFromString (mprpc.pas:~170-372): one
// blank/#127 separated record becomes one JSON object. Conversion failures
// that raise in Pascal (StrToBool / StrToInt64 on garbage) are returned as
// errors, which Response turns into JSON error 499.
func ObjectFromString(in string) (string, error) {
	in = strings.ReplaceAll(in, "\x7f", " ")
	p := func(n int64) string { return codec.Parameter(in, n) }
	i64def := func(n int64, def int64) int64 { return codec.StrToInt64Def(p(n), def) }
	i32def := func(n int64, def int64) int64 { return codec.StrToIntDef(p(n), def) }
	r := &obj{}
	switch p(0) {
	case "test":
		r.str("result", "testok")
	case "banned":
		r.str("result", "banned")
	case "restart":
		r.str("result", "True")
	case "balance":
		v, err := strToBool(p(1))
		if err != nil {
			return "", err
		}
		r.boolean("valid", v).str("address", p(2))
		if p(3) == "null" {
			r.null("alias")
		} else {
			r.str("alias", p(3))
		}
		for i, k := range []string{"balance", "incoming", "outgoing"} {
			x, ok := codec.StrToInt64(p(int64(4 + i)))
			if !ok {
				return "", errConv
			}
			r.i64(k, x)
		}
	case "orderinfo":
		v, err := strToBool(p(1))
		if err != nil {
			return "", err
		}
		r.boolean("valid", v)
		if v {
			o := &obj{}
			ts, ok1 := codec.StrToInt64(p(3))
			blk, ok2 := codec.StrToInt64(p(4))
			tr, ok3 := codec.StrToInt(p(6))
			am, ok4 := codec.StrToInt64(p(8))
			fe, ok5 := codec.StrToInt64(p(9))
			if !(ok1 && ok2 && ok3 && ok4 && ok5) {
				return "", errConv
			}
			o.str("orderid", p(2)).i64("timestamp", ts).i64("block", blk).str("type", p(5)).i64("trfrs", int64(tr)).
				str("receiver", p(7)).i64("amount", am).i64("fee", fe)
			if p(10) == "null" {
				o.null("reference")
			} else {
				o.str("reference", p(10))
			}
			o.str("sender", p(11))
			r.add("order", o.String())
		} else {
			r.null("order")
		}
	case "blockinfo":
		v, err := strToBool(p(1))
		if err != nil {
			return "", err
		}
		r.boolean("valid", v).i64("number", i32def(2, -1)).i64("timestart", i64def(3, -1)).i64("timeend", i64def(4, -1)).
			i64("timetotal", i32def(5, -1)).i64("last20", i32def(6, -1)).i64("totaltransactions", i32def(7, -1)).
			i64("difficulty", i32def(8, -1)).str("target", p(9)).str("solution", p(10)).str("lastblockhash", p(11)).
			i64("nextdifficult", i32def(12, -1)).str("miner", p(13)).i64("feespaid", i64def(14, -1)).
			i64("reward", i64def(15, -1)).str("hash", p(16))
	case "pendingorders", "lockedmns", "peers":
		var items []string
		for c := int64(1); p(c) != ""; c++ {
			items = append(items, jsonString(p(c)))
		}
		r.add(map[string]string{"pendingorders": "pendings", "lockedmns": "lockedmns", "peers": "peers"}[p(0)], arr(items))
	case "gvtinfo":
		r.i64("available", i32def(1, 0)).i64("buy", i64def(2, 0)).i64("sell", i64def(3, 0))
	case "mainnetinfo":
		pend, ok := codec.StrToInt(p(5))
		if !ok {
			return "", errConv
		}
		r.i64("lastblock", i32def(1, 0)).str("lastblockhash", p(2)).str("headershash", p(3)).str("sumaryhash", p(4)).
			i64("pending", int64(pend)).i64("supply", i64def(6, 0))
	case "blockorder":
		v, err := strToBool(p(1))
		if err != nil {
			return "", err
		}
		r.boolean("valid", v).i64("block", i32def(2, -1))
		cnt := i32def(3, 0)
		var items []string
		for c := int64(0); c < cnt; c++ {
			b := 4 + c*10
			items = append(items, (&obj{}).str("orderid", p(b)).i64("timestamp", i32def(b+1, 0)).i64("block", i32def(b+2, 0)).
				str("type", p(b+3)).i64("trfrs", i32def(b+4, 0)).str("receiver", p(b+5)).i64("amount", i64def(b+6, 0)).
				i64("fee", i32def(b+7, 0)).str("reference", p(b+8)).str("sender", p(b+9)).String())
		}
		r.add("orders", arr(items))
	case "blockmns":
		v, err := strToBool(p(1))
		if err != nil {
			return "", err
		}
		r.boolean("valid", v).i64("block", i32def(2, -1)).i64("count", i32def(3, -1)).i64("reward", i64def(4, -1)).
			i64("total", i64def(5, -1)).str("addresses", p(6))
	case "getmasternodes":
		r.i64("block", i32def(1, -1)).i64("count", i32def(2, -1)).str("nodes", p(3))
	case "newaddressfull":
		r.str("hash", p(1)).str("public", p(2)).str("private", p(3))
	case "newaddress":
		n := i32def(2, 1)
		var items []string
		for c := int64(1); c <= n; c++ {
			items = append(items, jsonString(p(2+c)))
		}
		r.add("addresses", arr(items))
	case "checkcertificate":
		if p(1) == "True" {
			t, ok := codec.StrToInt64(p(3))
			if !ok {
				return "", errConv
			}
			r.boolean("valid", true).str("address", p(2)).i64("signtime", t)
		} else {
			r.boolean("valid", false)
		}
	case "sendfunds":
		if p(1) == "ERROR" {
			r.boolean("valid", false).i64("result", i32def(2, -1))
		} else {
			r.boolean("valid", true).str("result", p(1))
		}
	case "islocaladdress", "setdefault", "submitorder":
		v, err := strToBool(p(1))
		if err != nil {
			return "", err
		}
		r.boolean("result", v)
	case "walletbalance":
		x, ok := codec.StrToInt64(p(1))
		if !ok {
			return "", errConv
		}
		r.i64("balance", x)
	case "submitorderwr":
		v, err := strToBool(p(1))
		if err != nil {
			return "", err
		}
		r.boolean("result", v).str("response", strings.ReplaceAll(p(2), "_", " "))
	}
	return r.String(), nil
}
