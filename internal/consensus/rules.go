// Package consensus holds the pure monetary and timing rules of the Noso
// chain: supply, block reward, reward splits and fees. Every function
// mirrors one Pascal routine and keeps its Int64/Integer arithmetic
// (truncating division, no overflow checks).
package consensus

import (
	"math"
	"math/bits"
	"strings"
)

// Chain constants (masterpaskalform.pas:586-615).
const (
	SecondsPerBlock      = 600
	PremineAmount        = 1030390730000
	InitialReward        = 5000000000
	BlockHalvingInterval = 210000
	HalvingSteps         = 10
	Comisiontrfr         = 10000
	MinimunFee           = 10
	PoSPercentage        = 1000
	MNsPercentage        = 2000
	PosStackCoins        = 20
	PoSBlockStart        = 8425
	PoSBlockEnd          = 88500 // COMPAT: a typed const (mutable var) in Pascal
	MNBlockStart         = 48010
	InitialBlockDiff     = 60
	GenesysTimeStamp     = 1615132800
	GenesisStartTime     = 1531896783 // mpblock.pas:150
	SecurityBlocks       = 4000
	SumMarkInterval      = 100
	Update050Block       = 120000
	ProjectFunds         = "NpryectdevepmentfundsGE"
	// AdminHash is only the miner address written into the genesis block
	// (history data, not a trust anchor).
	AdminHash = "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df"
)

// GetSupply returns the circulating supply after block `block`: the premine
// plus every reward paid for blocks 1..block under the real halving schedule.
// FIX(L-06): the original (nosogeneral.pas:213-223) ignored halvings after
// block 210000 and returned 0 from block 420000.
func GetSupply(block int64) int64 {
	if block < 0 {
		return 0
	}
	total := int64(PremineAmount)
	for from := int64(1); from <= block; {
		period := from / BlockHalvingInterval
		end := (period+1)*BlockHalvingInterval - 1
		if end > block {
			end = block
		}
		total += (end - from + 1) * GetBlockReward(from)
		from = end + 1
	}
	return total
}

// MaxSupply bounds any single amount (premine plus every reward ever paid).
// FIX(C-05).
var MaxSupply = GetSupply(BlockHalvingInterval * (HalvingSteps + 1))

// CheckedAdd adds two non-negative amounts and reports overflow or an amount
// beyond MaxSupply. FIX(C-05): the original added Int64 values without
// checks (mpprotocol.pas:782, nosounit.pas:407).
func CheckedAdd(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > MaxSupply || b > MaxSupply {
		return 0, false
	}
	return a + b, true
}

// GetBlockReward mirrors mpblock.pas:489-500: the premine for block 0,
// 5000000000 halved every 210000 blocks for 11 periods, then 0.
func GetBlockReward(n int64) int64 {
	switch {
	case n == 0:
		return PremineAmount
	case n > 0 && n < BlockHalvingInterval*(HalvingSteps+1):
		halvings := n / BlockHalvingInterval
		return InitialReward / (int64(1) << uint(halvings))
	}
	return 0
}

// Restar mirrors nosogeneral.pas:226-230.
func Restar(n int64) int64 {
	if n > 0 {
		return n - n*2
	}
	return n
}

// GetCustFee mirrors nosogeneral.pas:278-282.
func GetCustFee(block int64) int64 {
	if block < 162000 {
		return 25000
	}
	return 1000000
}

// GetStackRequired mirrors nosogeneral.pas:285-290 (the 1100000000000 cap
// is always overridden for blocks above 110000).
func GetStackRequired(block int64) int64 {
	r := GetSupply(block) * 20 / 10000
	if r > 1100000000000 {
		r = 1100000000000
	}
	if block > 110000 {
		r = 1050000000000
	}
	return r
}

// GetMNsPercentage mirrors nosogeneral.pas:293-303 (0..10000). COMPAT: the
// +1000 step uses 88400 while the PoS end constant elsewhere is 88500.
func GetMNsPercentage(block int64, mode string) int64 {
	var r int64
	if block >= 48010 {
		r = 2000 + ((block-48010)/4000)*100
		if block >= 88400 {
			r += 1000
		}
		if r > 6000 {
			r = 6000
		}
		if strings.Contains(mode, "MNSONLY") {
			r = 9000
		}
	}
	return r
}

// GetPoSPercentage mirrors nosogeneral.pas:306-316.
func GetPoSPercentage(block int64) int64 {
	var r int64
	if block > 8424 && block < 40000 {
		r = 1000
	}
	if block >= 40000 {
		r = 1000 + ((block-39000)/1000)*100
		if r > 2000 {
			r = 2000
		}
	}
	if block >= 88400 {
		r = 0
	}
	return r
}

// GetDevPercentage mirrors nosogeneral.pas:319-323.
func GetDevPercentage(block int64) int64 {
	if block >= 88400 {
		return 1000
	}
	return 0
}

// GetMinimumFee mirrors nosogeneral.pas:326-330.
func GetMinimumFee(amount int64) int64 {
	r := amount / Comisiontrfr
	if r < 1000000 {
		r = 1000000
	}
	return r
}

// GetMaximunToSend mirrors nosogeneral.pas:333-348.
func GetMaximunToSend(amount int64) int64 {
	if amount < 1000000 {
		return 0
	}
	maximo := amount * Comisiontrfr / (Comisiontrfr + 1)
	comision := maximo / Comisiontrfr
	if comision < 1000000 {
		comision = 1000000
	}
	envio := maximo + comision
	return maximo + (amount - envio)
}

// GetFee mirrors mpcoin.pas:265-269.
func GetFee(amount int64) int64 {
	r := amount / Comisiontrfr
	if r < MinimunFee {
		r = 1000000
	}
	return r
}

// BlockAge, NextBlockTimeStamp and IsBlockOpen mirror nosotime.pas:160-182
// for an explicit UTC time.
func BlockAge(utc int64) int64 { return utc % 600 }

// NextBlockTimeStamp is the timestamp of the next block boundary.
func NextBlockTimeStamp(utc int64) int64 { return utc + 600 - utc%600 }

// IsBlockOpen is false in the first 10 and last 15 seconds of a period.
func IsBlockOpen(utc int64) bool {
	a := BlockAge(utc)
	return !(a < 10 || a > 585)
}

// ApplyBP returns amount*bps/10000 (truncating) without Int64 overflow; ok is
// false for negative inputs or a result that does not fit. FIX(C-03): the
// original multiplied unchecked (mpblock.pas:300-310).
func ApplyBP(amount, bps int64) (int64, bool) {
	if amount < 0 || bps < 0 {
		return 0, false
	}
	hi, lo := bits.Mul64(uint64(amount), uint64(bps))
	if hi >= 10000 {
		return 0, false
	}
	q, _ := bits.Div64(hi, lo, 10000)
	if q > math.MaxInt64 {
		return 0, false
	}
	return int64(q), true
}

// MaxMasternodesPerBlock bounds the paid masternode list of one block.
const MaxMasternodesPerBlock = 5000

// Order caps of one block. TRFR and CUSTOM share the original 2000 limit
// (mpblock.pas:186); SNDGVT and the project payment have their own caps so
// that an honest builder can never produce a block the validator refuses.
const (
	MaxTransfersPerBlock = 2000
	MaxGVTPerBlock       = 100
)

// Shares splits one block: the project payment (from PoSBlockEnd), the
// masternode pay per node and the miner's remainder. FIX(M-10, C-03): the
// configuration mode no longer takes part (the original read MNSONLY from the
// local configuration, mpblock.pas:312), so every node derives the same
// split from the chain alone. ok is false when an amount does not fit.
func Shares(number, reward, fees int64, masternodes int) (dev, mnsPay, mnsTotal, pow int64, ok bool) {
	gross, okAdd := CheckedAdd(reward, fees)
	if !okAdd {
		return 0, 0, 0, 0, false
	}
	if number >= PoSBlockEnd {
		if dev, ok = ApplyBP(gross, GetDevPercentage(number)); !ok {
			return
		}
	}
	// FIX(re2 M-4): the masternode pool is reserved whatever list the proposer
	// publishes. Nodes that are not listed (or not there) do not enlarge the
	// proposer's remainder: the unpaid part is burnt. Only the proposer knows
	// the list, so the one rule that removes the incentive to shorten it is
	// that its length does not change what the proposer earns.
	var pool int64
	if number >= MNBlockStart {
		var okPool bool
		pool, okPool = ApplyBP(gross, GetMNsPercentage(number, ""))
		if !okPool {
			return 0, 0, 0, 0, false
		}
		if masternodes > 0 {
			mnsPay = pool / int64(masternodes)
			mnsTotal = mnsPay * int64(masternodes)
		}
	}
	pow = gross - dev - pool
	return dev, mnsPay, mnsTotal, pow, pow >= 0
}
