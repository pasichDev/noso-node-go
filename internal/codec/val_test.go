package codec

import (
	"strings"
	"testing"
)

// Expected values are DERIVED by hand from FPC 3.2.2 rtl/inc/sstrings.inc
// (InitVal, fpc_Val_SInt_ShortStr) and astrings.inc, not from a run of a
// Pascal binary (FPC is not installed). Assumption: x86_64, RTL without
// range checks.
func TestValDerivedFromFPCSource(t *testing.T) {
	type c struct {
		in    string
		want  int64
		fails bool
	}
	i64 := []c{
		{"x10", 16, false}, {"X10", 16, false}, {"$ff", 255, false}, {"0x10", 16, false},
		{"%101", 5, false}, {"&17", 15, false}, {" \t-12", -12, false}, {"+7", 7, false},
		{"x", 0, true}, {"$", 0, true}, {"-", 0, true}, {"", 0, true}, {" ", 0, true},
		{"12 ", 0, true}, {"1_0", 0, true}, {"0x", 0, true},
		{"000", 0, false}, {"-0", 0, false}, {"0000000000000000000000007", 7, false},
		{"9223372036854775807", 1<<63 - 1, false}, {"9223372036854775808", 0, true},
		{"-9223372036854775808", -1 << 63, false}, {"-9223372036854775809", 0, true},
		// non-decimal: unsigned 64-bit range, reinterpreted as signed
		{"$FFFFFFFFFFFFFFFF", -1, false}, {"$7FFFFFFFFFFFFFFF", 1<<63 - 1, false},
		{"$10000000000000000", 0, true}, {"-$FFFFFFFFFFFFFFFF", 1, false},
		// NUL ends the number; at the start only after a '0'
		{"12\x00z", 12, false}, {"0\x00", 0, false}, {"\x00", 0, true}, {"1\x00", 1, false}, {" \x00", 0, true},
		{"x\x00", 0, true}, {"-\x00", 0, true},
		// length over 255 is an error even if the value is fine
		{strings.Repeat("0", 300) + "5", 0, true}, {strings.Repeat("0", 254) + "5", 5, false},
		{strings.Repeat(" ", 255) + "5", 0, true},
	}
	for _, k := range i64 {
		v, ok := StrToInt64(k.in)
		if ok == k.fails || (ok && v != k.want) {
			t.Errorf("StrToInt64(%q) = %d,%v want %d fails=%v", k.in, v, ok, k.want, k.fails)
		}
	}
	i32 := []c{
		{"2147483647", 2147483647, false},
		{"2147483648", -2147483648, false}, // wraps, no error
		{"4294967301", 5, false},           // 2^32+5 truncates to 5
		{"-2147483649", 2147483647, false},
		{"$FFFFFFFF", -1, false}, // non-negative, non-decimal: sign-extended
		{"$80000000", -2147483648, false},
		{"$FFFFFFFFFFFFFFFF", -1, false},
		{"-$FFFFFFFF", 1, false}, // negative: no 32-bit sign extension, then wraps
		{"x05", 5, false}, {"abc", 0, true}, {"12\x00z", 12, false},
		{"9223372036854775808", 0, true},
	}
	for _, k := range i32 {
		v, ok := StrToInt(k.in)
		if ok == k.fails || (ok && int64(v) != k.want) {
			t.Errorf("StrToInt(%q) = %d,%v want %d fails=%v", k.in, v, ok, k.want, k.fails)
		}
	}
	if StrToIntDef("x05", 100) != 5 || StrToIntDef("4294967301", 100) != 5 || StrToIntDef("abc", 100) != 100 {
		t.Error("StrToIntDef")
	}
	if StrToInt64Def("x10", 1) != 16 || StrToInt64Def("", 9) != 9 {
		t.Error("StrToInt64Def")
	}
}

func TestStrToBoolLikeFPC(t *testing.T) {
	for in, want := range map[string]bool{"True": true, "FALSE": false, "0": false, "1": true, "-1": true, "2": true, "0.5": true, "0.0": false, "1e3": true} {
		if v, ok := TryStrToBool(in); !ok || v != want {
			t.Errorf("TryStrToBool(%q) = %v,%v", in, v, ok)
		}
	}
	for _, in := range []string{"", "yes", "tru", "1x", "0x1"} {
		if _, ok := TryStrToBool(in); ok {
			t.Errorf("TryStrToBool(%q) accepted", in)
		}
	}
	if !StrToBoolDef("maybe", true) || StrToBoolDef("maybe", false) {
		t.Error("default")
	}
}

func FuzzValInt(f *testing.F) {
	for _, s := range []string{"", "x10", "$ff", "-0", "12\x00z", "4294967301", strings.Repeat("9", 30)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := StrToInt64(s)
		if !ok && v != 0 {
			t.Fatalf("failed parse returned %d", v)
		}
		_, _ = StrToInt(s)
		_ = StrToIntDef(s, 3)
		_, _ = TryStrToBool(s)
	})
}

func TestUpperIsASCIIOnly(t *testing.T) {
	if got := ProCommand("a b c d $PıNG"); got != "$PıNG" {
		t.Errorf("dotless i folded: %q", got)
	}
	if got := ASCIIUpper("abc\xffxyzé"); got != "ABC\xffXYZé" {
		t.Errorf("%q", got)
	}
	if GetCommand("ping x") != "PING" {
		t.Error("ascii")
	}
}
