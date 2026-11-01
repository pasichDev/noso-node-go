package codec

import "testing"

func TestParameter(t *testing.T) {
	cases := []struct {
		in   string
		n    int64
		want string
	}{
		{"PSK 2 0.4.4Ab9 1700000000 $PING", 4, "$PING"},
		{"a  b", 1, ""},
		{"a  b", 2, "b"},
		{"a (b c) d", 1, "b c"},
		{"a (b (c)) d", 1, ""},
		{"x y", 5, ""},
		{"", 0, ""},
		{"a b ", 2, ""},
	}
	for _, c := range cases {
		if got := Parameter(c.in, c.n); got != c.want {
			t.Errorf("Parameter(%q,%d)=%q want %q", c.in, c.n, got, c.want)
		}
	}
	if Parameter("1.2.3.4", 2, '.') != "3" {
		t.Error("dot delimiter")
	}
}

func TestStrToInt(t *testing.T) {
	if v, ok := StrToInt64("0x10"); !ok || v != 16 {
		t.Error("0x10")
	}
	if v, ok := StrToInt64("$ff"); !ok || v != 255 {
		t.Error("$ff")
	}
	if _, ok := StrToInt64("12 "); ok {
		t.Error("trailing blank must fail")
	}
	// FPC 3.2.2 x86_64: Val range-checks against Int64 only; the narrowing to
	// Integer wraps (derivation in val.go and docs/compatibility.md).
	if v, ok := StrToInt("2147483648"); !ok || v != -2147483648 {
		t.Errorf("32-bit wrap: %d %v", v, ok)
	}
	if v, ok := StrToInt64("-9223372036854775808"); !ok || v != -1<<63 {
		t.Error("min int64")
	}
	if StrToIntDef("abc", 7) != 7 {
		t.Error("def")
	}
	if _, ok := StrToInt64(""); ok {
		t.Error("empty")
	}
}

// FIX(L-02): see codec.IsValidIP.
func TestIsValidIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"204.10.194.22": true, "38.242.252.153": true, "192.168.1.1": false, "127.0.0.1": false,
		"10.1.2.3": false, "172.16.0.1": false, "169.254.1.1": false, "224.0.0.1": false, "0.1.2.3": false,
		"256.1.1.1": false, "1.2.3": false, "1.2.3.4.5": false, "0x7f.0.0.1": false, "01.2.3.4": false,
		"1.2.3.": false, " 1.2.3.4": false,
	} {
		if IsValidIP(ip) != want {
			t.Errorf("IsValidIP(%q) want %v", ip, want)
		}
	}
}

// A network may allow masternodes on loopback and private addresses, and only
// those; every other special range stays refused.
func TestIsValidMNIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "172.16.0.9": true, "192.168.1.5": true, "8.8.8.8": true,
		"0.0.0.1": false, "169.254.1.1": false, "224.0.0.1": false, "100.64.0.1": false, "198.51.100.1": false,
		"172.32.0.1": true, "127.0.0.1.5": false, "0x7f.0.0.1": false, "127.00.0.1": false,
	} {
		local := IsValidMNIP(ip, true)
		if local != want {
			t.Errorf("local rule: %q = %v, want %v", ip, local, want)
		}
		strict := IsValidMNIP(ip, false)
		if strict != IsValidIP(ip) {
			t.Errorf("strict rule differs from IsValidIP for %q", ip)
		}
		if (ip == "127.0.0.1" || ip == "10.1.2.3" || ip == "192.168.1.5") && strict {
			t.Errorf("strict rule accepted %q", ip)
		}
	}
}
