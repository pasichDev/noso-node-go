package cli

import (
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/network"
)

func TestRunStatusReportsFailure(t *testing.T) {
	d := newDisp(t, false)
	var out []string
	say := func(s string) { out = append(out, s) }
	if !d.RunStatus("ver", say) {
		t.Fatal("ver failed")
	}
	for _, bad := range []string{"nosuchcommand", "sendto N1 10", "pubkey Nnotmine", "block 99999999", "newpso"} {
		if d.RunStatus(bad, say) {
			t.Errorf("%q reported success", bad)
		}
	}
}

func TestSendToNeedsAValidAmount(t *testing.T) {
	d := newDisp(t, true)
	for _, a := range []string{"1.123456789", "-1", "1e3", "abc", "1.", "0", "0.0"} {
		out := strings.Join(d.Run("sendto N3DthVsfEUtqrgWFHTEB6F88xLkT3Df "+a), "\n")
		if !strings.Contains(out, "Invalid ammount") {
			t.Errorf("amount %q: %q", a, out)
		}
	}
}

func TestParseAmount(t *testing.T) {
	good := map[string]int64{
		"1": 100000000, "10": 1000000000, "1.5": 150000000, "0.00000001": 1, "0.1": 10000000,
		"123.45678901": 12345678901, "150000000u": 150000000, "1u": 1, "0.29999999": 29999999,
	}
	for in, want := range good {
		got, err := network.ParseAmount(in)
		if err != nil || got != want {
			t.Errorf("ParseAmount(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "0.0", ".5", "1.", "-1", "+1", "1e3", "1,5", " 1", "1 ", "0.000000001", "u", "0u", "-5u",
		"1.5u", "99999999999999999999", "9999999999"} {
		if v, err := network.ParseAmount(in); err == nil {
			t.Errorf("ParseAmount(%q) = %d, want an error", in, v)
		}
	}
}

func TestControlRunnerWantsProofForKeys(t *testing.T) {
	d := newDisp(t, false)
	run := d.ControlRunner([]byte("correct horse battery"))
	key := d.N.Wallet.At(0).PrivateKey
	hash := d.N.Wallet.At(0).Hash
	call := func(line string, proof []byte) (string, bool) {
		var out []string
		ok := run(line, proof, func(s string) { out = append(out, s) })
		return strings.Join(out, "\n"), ok
	}
	for _, line := range []string{"showkeys " + hash, "expkeys " + hash, "expwallet x", "exportaddress " + hash, "signcfg 1", "directive 1 10 x"} {
		for _, proof := range [][]byte{nil, []byte("wrong"), []byte("correct horse batter")} {
			out, ok := call(line, proof)
			if ok || strings.Contains(out, key) {
				t.Errorf("%q with proof %q ran: %q", line, proof, out)
			}
		}
	}
	if out, ok := call("showkeys "+hash, []byte("correct horse battery")); !ok || !strings.Contains(out, key) {
		t.Fatalf("showkeys with the passphrase: %v %q", ok, out)
	}
	if _, ok := call("balance", nil); !ok {
		t.Fatal("an ordinary command needs no proof")
	}
	// a node opened without a passphrase offers no key command over the socket
	var o []string
	if ok := d.ControlRunner(nil)("showkeys "+hash, nil, func(s string) { o = append(o, s) }); ok || strings.Contains(strings.Join(o, ""), key) {
		t.Fatalf("an empty passphrase let a key through: %q", o)
	}
}
