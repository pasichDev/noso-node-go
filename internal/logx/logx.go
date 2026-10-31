// Package logx makes log output safe: peer-controlled text is escaped and
// truncated, and the line rate is bounded. FIX(L-07): the original wrote
// whatever a peer sent into its log files and memos without limit
// (nosodebug.pas:233-250).
package logx

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxLine is the longest logged line in bytes.
const MaxLine = 512

// Sanitize escapes control characters and cuts the text to MaxLine bytes.
func Sanitize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < MaxLine; i++ {
		c := s[i]
		switch {
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteByte(' ')
		case c < 32 || c == 127:
			b.WriteString(`\x` + strconv.FormatInt(int64(c)+256, 16)[1:])
		default:
			b.WriteByte(c)
		}
	}
	if len(s) > MaxLine || b.Len() > MaxLine {
		out := b.String()
		if len(out) > MaxLine {
			out = out[:MaxLine]
		}
		return out + "...[truncated]"
	}
	return b.String()
}

// Limiter admits at most Rate lines per second (burst Rate) and counts the
// dropped ones.
type Limiter struct {
	mu      sync.Mutex
	Rate    int
	tokens  float64
	last    time.Time
	Dropped int
	Now     func() time.Time
}

// Allow reports whether a line may be written now.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	if l.last.IsZero() {
		l.tokens, l.last = float64(l.Rate), now
	}
	l.tokens += now.Sub(l.last).Seconds() * float64(l.Rate)
	if l.tokens > float64(l.Rate) {
		l.tokens = float64(l.Rate)
	}
	l.last = now
	if l.tokens < 1 {
		l.Dropped++
		return false
	}
	l.tokens--
	return true
}
