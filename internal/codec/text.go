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
func GetCommand(line string) string { return strings.ToUpper(Parameter(line, 0)) }

// ProCommand is nosogeneral.pas:188-191 (the command of a protocol line).
func ProCommand(line string) string { return strings.ToUpper(Parameter(line, 4)) }

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

// IsValidIP mirrors nosogeneral.pas:194-210 including its leniency:
// numeric fields use Val syntax and any number of trailing octets is
// ignored; 192.168.x.x and 127.0.x.x are rejected.
func IsValidIP(ip string) bool {
	v := [4]int64{}
	for i := range v {
		v[i] = StrToIntDef(Parameter(ip, int64(i), '.'), -1)
	}
	ok := true
	for _, x := range v {
		if x < 0 || x > 255 {
			ok = false
		}
	}
	if v[0] == 192 && v[1] == 168 {
		ok = false
	}
	if v[0] == 127 && v[1] == 0 {
		ok = false
	}
	return ok
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

// ASCIIUpper mirrors UpperCase (ASCII only, like FPC without locale tables).
func ASCIIUpper(s string) string { return strings.ToUpper(asciiOnly(s)) }

func asciiOnly(s string) string { return s }

// Pos mirrors Pascal pos(): 1-based index or 0.
func Pos(sub, s string) int { return strings.Index(s, sub) + 1 }

// AnsiContainsStr mirrors StrUtils.AnsiContainsStr (case sensitive).
func AnsiContainsStr(s, sub string) bool { return strings.Contains(s, sub) }
