package network

// setConsensusForTest sets one consensus item, growing the list if needed.
func (e *Engine) setConsensusForTest(i int, v string) {
	e.consMu.Lock()
	defer e.consMu.Unlock()
	for len(e.cons) <= i || len(e.cons) < len(NConsensus) {
		e.cons = append(e.cons, "")
	}
	e.cons[i] = v
}
