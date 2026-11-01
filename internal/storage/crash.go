package storage

// Crash injection for the durability tests. Production code never sets
// CrashHook; every call is then a nil check. A test arms the hook and panics
// from it at the n-th point, which stands in for a power loss: nothing after
// that point in the interrupted operation runs.
var CrashHook func(point string)

// Crashed is set by the test that panics from CrashHook. A real crash runs no
// deferred cleanup, so cleanup helpers consult it and do nothing.
var Crashed bool

// Crash marks a point at which the process may die.
func Crash(point string) {
	if CrashHook != nil {
		CrashHook(point)
	}
}
