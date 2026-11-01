package rpc

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/node"
)

// The request is parsed like the original: exact member names, nothing after
// the JSON value, a null id is no id.
func TestStrictRequestShape(t *testing.T) {
	s := newServer(t)
	for _, in := range []string{
		`{"jsonrpc":"2.0","METHOD":"test","params":[],"id":1}`,
		`{"jsonrpc":"2.0","method":"test","params":[],"id":null}`,
	} {
		if got := s.Parse(in); got != "" {
			t.Errorf("%s: want an empty body, got %s", in, got)
		}
	}
	if got := s.Parse(`{"jsonrpc":"2.0","method":"test","params":[],"id":1} trailing`); !strings.Contains(got, `"code":401`) {
		t.Errorf("trailing text accepted: %s", got)
	}
}

// restart answers True only when something can restart (finding 12).
func TestRestartOnlyWhenAvailable(t *testing.T) {
	s := newServer(t)
	call := `{"jsonrpc":"2.0","method":"restart","params":[],"id":1}`
	if got := s.parse(call, true); !strings.Contains(got, `"code":402`) {
		t.Fatalf("restart answered without a restart hook: %s", got)
	}
	done := make(chan struct{})
	s.Restart = func() { close(done) }
	if got := s.parse(call, true); !strings.Contains(got, `"result":"True"`) {
		t.Fatalf("restart refused: %s", got)
	}
	<-done
}

// islocaladdress works on an encrypted wallet and RPCSaveNew leaves no
// plaintext key file (findings 10, 20).
func TestLocalAddressAndNoPlaintextKeys(t *testing.T) {
	s := newServer(t)
	s.N.UpdateOptions(func(o *node.StorageOptions) { o.RPCSaveNew = true })
	w, err := s.E.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	got := s.parse(`{"jsonrpc":"2.0","method":"islocaladdress","params":["`+w.Hash+`"],"id":1}`, false)
	if !strings.Contains(got, `"result":true`) {
		t.Fatalf("own address not recognised: %s", got)
	}
	if got := s.parse(`{"jsonrpc":"2.0","method":"islocaladdress","params":["N24oBNscYwaVc6yKRzyUcTznUGcbcGW"],"id":1}`, false); !strings.Contains(got, `"result":false`) {
		t.Fatalf("foreign address reported local: %s", got)
	}
	s.parse(`{"jsonrpc":"2.0","method":"getnewaddress","params":[2],"id":1}`, true)
	s.parse(`{"jsonrpc":"2.0","method":"getnewaddressfull","params":[],"id":1}`, true)
	matches, _ := filepath.Glob(filepath.Join(s.N.Lay.RPCBakDir, "*"))
	if len(matches) != 0 {
		t.Fatalf("plaintext key files written: %v", matches)
	}
}

// L7: an IPv6 caller is not matched by the end-of-list marker.
func TestL7_IPv6Whitelist(t *testing.T) {
	if ValidRPCHost("127.0.0.1,localhost", "[::1]:5000") || ValidRPCHost("127.0.0.1", "") {
		t.Fatal("IPv6 caller passed a whitelist without it")
	}
	if !ValidRPCHost("127.0.0.1,::1", "[::1]:5000") || !ValidRPCHost("127.0.0.1,localhost", "127.0.0.1:80") {
		t.Fatal("whitelisted caller refused")
	}
}

// F-15: Stop waits for the requests in flight, so none goes on after it returns.
func TestStopWaitsForRequestsInFlight(t *testing.T) {
	s := newServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var finished atomic.Bool
	started := make(chan struct{})
	s.mu.Lock()
	s.ln = ln
	s.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		finished.Store(true)
	})}
	go func() { _ = s.srv.Serve(ln) }()
	s.mu.Unlock()
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started
	s.Stop()
	if !finished.Load() {
		t.Fatal("Stop returned while a request was still being served")
	}
}
