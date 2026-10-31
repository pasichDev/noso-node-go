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
	if _, ok := StrToInt("2147483648"); ok {
		t.Error("overflow must fail")
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

func TestIsValidIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"204.10.194.22": true, "192.168.1.1": false, "127.0.0.1": false,
		"256.1.1.1": false, "1.2.3": false, "1.2.3.4.5": true,
	} {
		if IsValidIP(ip) != want {
			t.Errorf("IsValidIP(%q)", ip)
		}
	}
}
