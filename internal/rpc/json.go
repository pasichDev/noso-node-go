// Package rpc implements the JSON-RPC 2.0 server of the Noso node with the
// exact methods, parameters and response shapes of mprpc.pas.
package rpc

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// jsonString escapes s like FPC's StringToJSONString: quote, backslash and
// forward slash are escaped, control characters use \b \f \n \r \t or
// \u00XX, and non-ASCII runes are written as \uXXXX (surrogate pairs above
// the BMP). The input is treated as UTF-8.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// not UTF-8: keep the raw byte as a Latin-1 code point
			writeU(&b, rune(s[i]))
			i++
			continue
		}
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '/':
			b.WriteString(`\/`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 || r > 126 {
				if r > 0xFFFF {
					r -= 0x10000
					writeU(&b, 0xD800+(r>>10))
					writeU(&b, 0xDC00+(r&0x3FF))
				} else {
					writeU(&b, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func writeU(b *strings.Builder, r rune) {
	h := strconv.FormatInt(int64(r), 16)
	b.WriteString(`\u` + strings.Repeat("0", 4-len(h)) + strings.ToUpper(h))
}

// obj builds a JSON object keeping insertion order (TJSONObject.Add).
type obj struct {
	keys []string
	vals []string
}

func (o *obj) add(k, raw string) *obj {
	o.keys = append(o.keys, k)
	o.vals = append(o.vals, raw)
	return o
}

func (o *obj) str(k, v string) *obj       { return o.add(k, jsonString(v)) }
func (o *obj) i64(k string, v int64) *obj { return o.add(k, strconv.FormatInt(v, 10)) }
func (o *obj) boolean(k string, v bool) *obj {
	if v {
		return o.add(k, "true")
	}
	return o.add(k, "false")
}
func (o *obj) null(k string) *obj { return o.add(k, "null") }

func (o *obj) String() string {
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(k))
		b.WriteByte(':')
		b.WriteString(o.vals[i])
	}
	b.WriteByte('}')
	return b.String()
}

func arr(items []string) string { return "[" + strings.Join(items, ",") + "]" }
