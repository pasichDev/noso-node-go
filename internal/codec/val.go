package codec

import "strconv"

// valInt mirrors Free Pascal's Val() for signed integers, which StrToInt,
// StrToInt64 and their *Def variants delegate to. Quirks preserved:
// leading blanks/tabs allowed, trailing characters not; optional sign;
// base prefixes "$", "0x"/"0X", "&" (octal) and "%" (binary) are accepted;
// the value must fit [min, max].
func valInt(s string, min, max int64) (int64, bool) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	base := uint64(10)
	if i < len(s) {
		switch {
		case s[i] == '$':
			base = 16
			i++
		case s[i] == '%':
			base = 2
			i++
		case s[i] == '&':
			base = 8
			i++
		case s[i] == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X'):
			base = 16
			i += 2
		}
	}
	if i >= len(s) {
		return 0, false
	}
	var acc uint64
	limit := uint64(max)
	if neg {
		limit = uint64(-(min + 1)) + 1
	}
	for ; i < len(s); i++ {
		c := s[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if d >= base {
			return 0, false
		}
		if acc > (limit-d)/base {
			return 0, false
		}
		acc = acc*base + d
	}
	if neg {
		return -int64(acc-1) - 1, true
	}
	return int64(acc), true
}

// StrToInt64 mirrors SysUtils.StrToInt64; ok is false where Pascal raises
// EConvertError.
func StrToInt64(s string) (int64, bool) { return valInt(s, -1<<63, 1<<63-1) }

// StrToInt mirrors SysUtils.StrToInt (32-bit Integer).
func StrToInt(s string) (int32, bool) {
	v, ok := valInt(s, -1<<31, 1<<31-1)
	return int32(v), ok
}

// StrToIntDef mirrors StrToIntDef (32-bit range, default on failure).
func StrToIntDef(s string, def int64) int64 {
	v, ok := valInt(s, -1<<31, 1<<31-1)
	if !ok {
		return def
	}
	return v
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

// StrToBoolDef mirrors SysUtils.StrToBoolDef for the default TrueBoolStrs /
// FalseBoolStrs ("true"/"false" case-insensitively) and numeric strings
// (non-zero = true).
func StrToBoolDef(s string, def bool) bool {
	switch ASCIIUpper(s) {
	case "TRUE", "-1":
		return true
	case "FALSE":
		return false
	}
	if v, ok := valInt(s, -1<<63, 1<<63-1); ok {
		return v != 0
	}
	return def
}
