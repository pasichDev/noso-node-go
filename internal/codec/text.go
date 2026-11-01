// Package codec holds the Free Pascal compatibility primitives used by every
// other package: ShortString and packed-record byte layout, Val-style number
// parsing, the Parameter tokenizer and Indy-style line framing.
package codec

import "strings"

// Parameter mirrors nosogeneral.pas:133-181 exactly, including the
// parenthesis quirks: a "(" opens a group in which the delimiter is kept
// literally, a second "(" inside a group makes the whole call return "", and
// ")" closes the group. The "(" and ")" characters are never copied.
func Parameter(line string, n int64, delim ...byte) string {
	d := byte(' ')
	if len(delim) > 0 {
		d = delim[0]
	}
	var temp []byte
	var spaces int64
	paren := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '(' && !paren:
			paren = true
		case c == '(' && paren:
			return ""
		case c == ')' && paren:
			if spaces == n {
				return string(temp)
			}
			paren = false
			temp = temp[:0]
		case c == d && !paren:
			spaces++
			if spaces > n {
				return string(temp)
			}
		case c == d && paren && spaces == n:
			temp = append(temp, c)
		case spaces == n:
			temp = append(temp, c)
		}
	}
	// nosogeneral.pas:179 `if temp = de_limit then temp := ''`
	if len(temp) == 1 && temp[0] == d {
		return ""
	}
	return string(temp)
}

// GetCommand is nosogeneral.pas:183-186.
func GetCommand(line string) string { return ASCIIUpper(Parameter(line, 0)) }

// ProCommand is nosogeneral.pas:188-191 (the command of a protocol line).
func ProCommand(line string) string { return ASCIIUpper(Parameter(line, 4)) }

// GetOpData is mpparser.pas:178-183: everything from the first '$'. Pascal
// copy(s, 0, n) with pos=0 returns the whole line, which is mirrored.
func GetOpData(line string) string {
	p := strings.IndexByte(line, '$')
	if p < 0 {
		return line
	}
	return line[p:]
}

// ExtractMNsText is nosogeneral.pas:627-635: text after the first '$'
// (whole string if there is none).
func ExtractMNsText(s string) string {
	p := strings.IndexByte(s, '$')
	if p < 0 {
		return s
	}
	return s[p+1:]
}

// IsValidIP accepts only a public unicast IPv4 address written as exactly
// four decimal parts. FIX(L-02): the original (nosogeneral.pas:194-210)
// accepted forms such as "1.2.3.4.5", "0x7f.0.0.1", and every private,
// loopback, link-local, multicast and reserved range except 192.168/16 and
// 127.0/16.
func IsValidIP(ip string) bool { return IsValidMNIP(ip, false) }

// IsValidMNIP is IsValidIP for the address of a masternode. With local set
// (the local_masternodes rule of a network, which comes only from its network
// file) loopback and private-use ranges (127/8, 10/8, 172.16/12, 192.168/16)
// are accepted as well; every other special range stays refused.
func IsValidMNIP(ip string, local bool) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	var v [4]int
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range []byte(p) {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		v[i] = n
	}
	if local {
		switch {
		case v[0] == 127, v[0] == 10, v[0] == 172 && v[1] >= 16 && v[1] <= 31, v[0] == 192 && v[1] == 168:
			return true
		}
	}
	switch {
	case v[0] == 0, v[0] == 10, v[0] == 127, v[0] >= 224:
		return false
	case v[0] == 100 && v[1] >= 64 && v[1] <= 127: // CGNAT
		return false
	case v[0] == 169 && v[1] == 254, v[0] == 172 && v[1] >= 16 && v[1] <= 31, v[0] == 192 && v[1] == 168:
		return false
	case v[0] == 192 && v[1] == 0 && v[2] == 0, v[0] == 192 && v[1] == 0 && v[2] == 2,
		v[0] == 198 && (v[1] == 18 || v[1] == 19), v[0] == 198 && v[1] == 51 && v[2] == 100,
		v[0] == 203 && v[1] == 0 && v[2] == 113:
		return false
	}
	return true
}

// Copy mirrors the Pascal copy(s, idx, count) on 1-based indexes, clamped
// like FPC does (idx<1 is treated as 1, past-the-end yields "").
func Copy(s string, idx, count int) string {
	if idx < 1 {
		idx = 1
	}
	if count < 0 || idx > len(s) {
		return ""
	}
	end := idx - 1 + count
	if end > len(s) {
		end = len(s)
	}
	return s[idx-1 : end]
}

// Trim mirrors SysUtils.Trim: strips bytes <= ' ' from both ends.
func Trim(s string) string {
	a, b := 0, len(s)
	for a < b && s[a] <= ' ' {
		a++
	}
	for b > a && s[b-1] <= ' ' {
		b--
	}
	return s[a:b]
}

// ASCIIUpper mirrors UpperCase: only the bytes a-z change; every other byte
// (including each byte of a multi-byte UTF-8 sequence, and invalid UTF-8)
// is kept as it is.
func ASCIIUpper(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'a' || s[i] > 'z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// Pos mirrors Pascal pos(): 1-based index or 0.
func Pos(sub, s string) int { return strings.Index(s, sub) + 1 }

// AnsiContainsStr mirrors StrUtils.AnsiContainsStr (case sensitive).
func AnsiContainsStr(s, sub string) bool { return strings.Contains(s, sub) }
