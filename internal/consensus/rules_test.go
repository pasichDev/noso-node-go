package consensus

import "testing"

// Hand-derived vectors from the Pascal source. Each cites the routine.
func TestBlockRewardBoundaries(t *testing.T) {
	cases := []struct {
		h    int64
		want int64
	}{
		{0, 1030390730000},   // mpblock.pas:493 premine
		{1, 5000000000},      // 1 div 210000 = 0 halvings
		{209999, 5000000000}, // last block before the first halving
		{210000, 2500000000}, // mpblock.pas:496-497, 1 halving
		{419999, 2500000000},
		{420000, 1250000000},
		{210000 * 10, 5000000000 / 1024},   // 10th halving: 4882812 (truncated)
		{210000*11 - 1, 5000000000 / 1024}, // last block with a reward
		{210000 * 11, 0},                   // mpblock.pas:498-499: 2310000 -> 0
		{-1, 0},
	}
	for _, c := range cases {
		if got := GetBlockReward(c.h); got != c.want {
			t.Errorf("GetBlockReward(%d)=%d want %d", c.h, got, c.want)
		}
	}
	if GetBlockReward(210000*10) != 4882812 {
		t.Error("truncating division at 10 halvings")
	}
}

// FIX(L-06): supply follows the real halving schedule.
func TestSupply(t *testing.T) {
	if GetSupply(0) != 1030390730000 || GetSupply(100) != 100*5000000000+1030390730000 {
		t.Error("supply low")
	}
	if GetSupply(209999) != 209999*5000000000+1030390730000 || GetSupply(210000) != 209999*5000000000+2500000000+1030390730000 {
		t.Error("supply around the first halving")
	}
	// independent summation
	var sum int64 = 1030390730000
	for b := int64(1); b <= 450000; b++ {
		sum += GetBlockReward(b)
	}
	if GetSupply(450000) != sum {
		t.Errorf("%d != %d", GetSupply(450000), sum)
	}
	if GetSupply(420000) == 0 || GetSupply(2310000) != GetSupply(5000000) {
		t.Error("supply after 420000 / end of rewards")
	}
	if _, ok := CheckedAdd(MaxSupply, 1<<62); ok {
		t.Error("overflow accepted")
	}
	if _, ok := CheckedAdd(-1, 5); ok {
		t.Error("negative accepted")
	}
}

func TestPercentages(t *testing.T) {
	// nosogeneral.pas:296-300
	if GetMNsPercentage(48009, "NORMAL") != 0 || GetMNsPercentage(48010, "NORMAL") != 2000 {
		t.Error("mn start")
	}
	if GetMNsPercentage(52009, "NORMAL") != 2000 || GetMNsPercentage(52010, "NORMAL") != 2100 {
		t.Error("mn step 4000")
	}
	if GetMNsPercentage(88399, "NORMAL") != 2000+((88399-48010)/4000)*100 { // 2900
		t.Error("before 88400")
	}
	if GetMNsPercentage(88400, "NORMAL") != 2000+((88400-48010)/4000)*100+1000 { // 3900
		t.Error("at 88400")
	}
	if GetMNsPercentage(10000000, "NORMAL") != 6000 {
		t.Error("cap")
	}
	if GetMNsPercentage(100000, "MNSONLY") != 9000 || GetMNsPercentage(10, "MNSONLY") != 0 {
		t.Error("mnsonly applies only after start")
	}
	// PoS
	if GetPoSPercentage(8424) != 0 || GetPoSPercentage(8425) != 1000 || GetPoSPercentage(39999) != 1000 {
		t.Error("pos early")
	}
	if GetPoSPercentage(40000) != 1000+((40000-39000)/1000)*100 || GetPoSPercentage(88399) != 2000 {
		t.Error("pos late")
	}
	if GetPoSPercentage(88400) != 0 {
		t.Error("pos end at 88400, not 88500")
	}
	if GetDevPercentage(88399) != 0 || GetDevPercentage(88400) != 1000 {
		t.Error("dev")
	}
}

func TestFees(t *testing.T) {
	if GetMinimumFee(0) != 1000000 || GetMinimumFee(10_000_000_000) != 1000000 || GetMinimumFee(20_000_000_000) != 2000000 {
		t.Error("minimum fee")
	}
	if GetFee(5) != 1000000 || GetFee(1_000_000_000_000) != 100_000_000 {
		t.Error("GetFee")
	}
	// GetMaximunToSend(amount): max = amount*10000 div 10001.
	if GetMaximunToSend(999999) != 0 {
		t.Error("below min fee")
	}
	a := int64(100_000_000_000)
	max := a * 10000 / 10001
	want := max + (a - (max + max/10000))
	if GetMaximunToSend(a) != want {
		t.Errorf("%d != %d", GetMaximunToSend(a), want)
	}
	if GetCustFee(161999) != 25000 || GetCustFee(162000) != 1000000 {
		t.Error("custom fee boundary 162000")
	}
	if GetStackRequired(110000) != 1100000000000 /* capped, nosogeneral.pas:288 */ || GetStackRequired(1000) != GetSupply(1000)*20/10000 || GetStackRequired(110001) != 1050000000000 {
		t.Error("stack")
	}
}

func TestBlockTiming(t *testing.T) {
	if BlockAge(1200) != 0 || BlockAge(1799) != 599 {
		t.Error("age")
	}
	if NextBlockTimeStamp(1200) != 1800 || NextBlockTimeStamp(1799) != 1800 {
		t.Error("next")
	}
	for age, open := range map[int64]bool{9: false, 10: true, 585: true, 586: false} {
		if IsBlockOpen(6000+age) != open {
			t.Errorf("age %d", age)
		}
	}
}
