package cli

import (
	"strings"
	"testing"
)

// restorecfg must not silently cut the node off from its peers.
func TestRestoreCFGKeepsSeeds(t *testing.T) {
	d := newDisp(t, true)
	d.Run("clearcfg 1")
	d.Run("addnode 10.0.0.1;8080")
	out := strings.Join(d.Run("restorecfg"), "\n")
	if got := d.E.NodesList(); len(got) != 1 || got[0] != "10.0.0.1:8080" {
		t.Fatalf("seeds after restorecfg: %v (%s)", got, out)
	}
	if !strings.Contains(out, "seed list was kept") {
		t.Fatalf("restorecfg said nothing about the seeds: %q", out)
	}
	out = strings.Join(d.Run("restorecfg seeds"), "\n")
	if got := d.E.NodesList(); len(got) != 0 {
		t.Fatalf("restorecfg seeds kept %v", got)
	}
	if !strings.Contains(out, "no peers") {
		t.Fatalf("the full reset does not warn: %q", out)
	}
}

// newpso and clearpsos changed the state root of one node only; they are gone.
func TestPSOCommandsDoNotTouchTheState(t *testing.T) {
	d := newDisp(t, false)
	before := d.N.PSOs.FileHash()
	for _, c := range []string{"newpso", "clearpsos"} {
		out := strings.Join(d.Run(c), "\n")
		if !(strings.Contains(out, "removed") || strings.Contains(out, "blocks")) {
			t.Errorf("%s: %q", c, out)
		}
	}
	if d.N.PSOs.FileHash() != before {
		t.Fatal("a PSO command changed the PSO file")
	}
}
