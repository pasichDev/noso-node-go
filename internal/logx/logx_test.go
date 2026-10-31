package logx

import (
	"strings"
	"testing"
	"time"
)

// L-07: control characters are escaped, long text is cut, the rate bounded.
func TestL07(t *testing.T) {
	got := Sanitize("PSK\r\nFAKE LOG LINE\x1b[31m" + strings.Repeat("A", 5000))
	if strings.ContainsAny(got, "\r\n\x1b") || len(got) > MaxLine+20 || !strings.HasSuffix(got, "[truncated]") {
		t.Fatalf("%q", got[:60])
	}
	now := time.Unix(1000, 0)
	l := &Limiter{Rate: 10, Now: func() time.Time { return now }}
	ok := 0
	for i := 0; i < 1000; i++ {
		if l.Allow() {
			ok++
		}
	}
	if ok != 10 || l.Dropped != 990 {
		t.Fatalf("burst %d dropped %d", ok, l.Dropped)
	}
	now = now.Add(time.Second)
	if !l.Allow() {
		t.Fatal("tokens do not refill")
	}
}
