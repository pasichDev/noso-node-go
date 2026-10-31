package codec

import "strconv"

// valInt reproduces Free Pascal 3.2.2 (x86_64) Val() for signed integers,
// which StrToInt, StrToInt64 and their *Def variants delegate to. It follows
// rtl/inc/sstrings.inc (InitVal, fpc_Val_SInt_ShortStr) and astrings.inc
// (fpc_Val_SInt_AnsiStr) statement by statement. ASSUMPTION (docs/
// compatibility.md, "FPC assumptions"): FPC 3.2.2, 64-bit CPU, RTL built
// without range checks, i.e. ValSInt is Int64 and the narrowing to Integer
// in StrToInt truncates.
//
// Behaviour, all of it deliberate:
//   - a string longer than 255 bytes fails (AnsiString to ShortString);
//   - leading blanks and tabs are skipped, trailing characters are an error;
//   - optional sign, then a base prefix: "$", "x", "X" (hex, bare x is a
//     prefix), "%" (binary), "&" (octal), "0x"/"0X" (hex);
//   - leading zeros are stripped, but the last character is always kept;
//   - a NUL ends the number successfully (but a NUL right at the start of
//     the digits only counts as zero when a '0' precedes it);
//   - base 10 is checked against the 64-bit range (2^63-1, or 2^63 when
//     negative); any other base against the unsigned 64-bit range, and the
//     unsigned value is then reinterpreted as signed (so "$FFFFFFFFFFFFFFFF"
//     is -1) and, for a 4 byte destination, sign-extended from 32 bits when
//     not negative;
//   - the final narrowing to 32 bits (StrToInt) wraps without an error.
func valInt(s string, destSize int) (int64, bool) {
	if len(s) > 255 {
		return 0, false
	}
	n := len(s)
	if n == 0 {
		return 0, false
	}
	c := 0 // 0-based index, FPC code-1
	for c < n && (s[c] == ' ' || s[c] == '\t') {
		c++
	}
	if c >= n {
		return 0, false
	}
	neg := false
	switch s[c] {
	case '-':
		neg = true
		c++
	case '+':
		c++
	}
	base := uint64(10)
	if c < n {
		switch s[c] {
		case '$', 'X', 'x':
			base = 16
			c++
		case '%':
			base = 2
			c++
		case '&':
			base = 8
			c++
		case '0':
			if c+1 < n && (s[c+1] == 'x' || s[c+1] == 'X') {
				c += 2
				base = 16
			}
		}
	}
	for c+1 < n && s[c] == '0' { // strip leading zeros, keep the last char
		c++
	}
	if c >= n {
		return 0, false
	}
	if s[c] == 0 {
		if c > 0 && s[c-1] == '0' {
			return 0, true
		}
		return 0, false
	}
	maxPrev := ^uint64(0) / base
	maxNew := ^uint64(0)
	if base == 10 {
		maxNew = 1<<63 - 1
		if neg {
			maxNew++
		}
	}
	var temp uint64
	for ; c < n; c++ {
		var u uint64
		ch := s[c]
		if ch == 0 {
			break // NUL ends the number
		}
		switch {
		case ch >= '0' && ch <= '9':
			u = uint64(ch - '0')
		case ch >= 'A' && ch <= 'F':
			u = uint64(ch-'A') + 10
		case ch >= 'a' && ch <= 'f':
			u = uint64(ch-'a') + 10
		default:
			u = 16
		}
		prev := temp
		temp *= base
		if u >= base || maxNew-u < temp || prev > maxPrev {
			return 0, false
		}
		temp += u
	}
	v := int64(temp)
	if neg {
		v = -v
	}
	if !neg && base != 10 && destSize == 4 {
		v = int64(int32(v))
	}
	return v, true
}

// StrToInt64 mirrors SysUtils.StrToInt64; ok is false where Pascal raises
// EConvertError.
func StrToInt64(s string) (int64, bool) { return valInt(s, 8) }

// StrToInt mirrors SysUtils.StrToInt (32-bit Integer). A value outside the
// 32-bit range is not an error on FPC 3.2.2 x86_64: it wraps (see valInt).
func StrToInt(s string) (int32, bool) {
	v, ok := valInt(s, 4)
	return int32(v), ok
}

// StrToIntDef mirrors StrToIntDef (32-bit wrap, default on failure).
func StrToIntDef(s string, def int64) int64 {
	v, ok := valInt(s, 4)
	if !ok {
		return def
	}
	return int64(int32(v))
}

// StrToInt64Def mirrors StrToInt64Def.
func StrToInt64Def(s string, def int64) int64 {
	v, ok := StrToInt64(s)
	if !ok {
		return def
	}
	return v
}

// IntToStr mirrors IntToStr.
func IntToStr(v int64) string { return strconv.FormatInt(v, 10) }

// StrToBoolDef mirrors SysUtils.StrToBoolDef (TryStrToBool).
func StrToBoolDef(s string, def bool) bool {
	if v, ok := TryStrToBool(s); ok {
		return v
	}
	return def
}

// TryStrToBool mirrors SysUtils.TryStrToBool (sysstr.inc): the upper-cased
// text is first read as a Double (any non-zero number is true, "0.5" and "2"
// included), then compared with "TRUE" / "FALSE".
func TryStrToBool(s string) (value, ok bool) {
	t := ASCIIUpper(s)
	if f, isNum := valDouble(t); isNum {
		return f != 0, true
	}
	switch t {
	case "TRUE":
		return true, true
	case "FALSE":
		return false, true
	}
	return false, false
}

// valDouble approximates Val() into a Double: optional leading blanks, sign,
// digits with one optional point, optional exponent; nothing may follow.
func valDouble(s string) (float64, bool) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	t := s[i:]
	if t == "" {
		return 0, false
	}
	for j := 0; j < len(t); j++ {
		switch c := t[j]; {
		case c >= '0' && c <= '9', c == '.', c == '+', c == '-', c == 'E':
		default:
			return 0, false
		}
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f, true
		}
		return 0, false
	}
	return f, true
}
