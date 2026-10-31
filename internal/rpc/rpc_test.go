package rpc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
)

func newServer(t *testing.T) *Server {
	n, err := node.New(filepath.Join(t.TempDir(), "NOSODATA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("../../testdata/59238.psk")
	if err := n.Summary.Replace(raw); err != nil {
		t.Fatal(err)
	}
	return New(network.NewEngine(n))
}

func TestShapes(t *testing.T) {
	s := newServer(t)
	cases := []struct{ in, want string }{
		{`{"jsonrpc":"2.0","method":"test","params":[],"id":7}`,
			`{"jsonrpc":"2.0","result":[{"result":"testok"}],"id":7}`},
		{`{"jsonrpc":"2.0","method":"nope","params":[],"id":7}`,
			`{"jsonrpc":"2.0","error":{"code":402,"message":"Invalid method"},"id":-1}`},
		{`not json`, `{"jsonrpc":"2.0","error":{"code":401,"message":"Invalid JSON request"},"id":-1}`},
		{`{"jsonrpc":"2.0","params":[],"id":1}`, ``}, // COMPAT: raises inside try/except, empty body
		{`{"jsonrpc":"2.0","method":"getaddressbalance","params":["AllForOne","N24oBNscYwaVc6yKRzyUcTznUGcbcGW","Nunknown"],"id":3}`,
			`{"jsonrpc":"2.0","result":[` +
				`{"valid":true,"address":"N7kKEo1LLdmd6QwEff1hC7bdMUeCCc","alias":"AllForOne","balance":0,"incoming":0,"outgoing":0},` +
				`{"valid":true,"address":"N24oBNscYwaVc6yKRzyUcTznUGcbcGW","alias":"Aelis","balance":643228805230,"incoming":0,"outgoing":0}],"id":3}`}, // "Nunknown" yields nothing: not an address, alias lookup gives Hash=''

		{`{"jsonrpc":"2.0","method":"getgvtinfo","params":[],"id":4}`,
			`{"jsonrpc":"2.0","result":[{"available":0,"buy":3168147889690,"sell":2692925706236}],"id":4}`},
	}
	for _, c := range cases {
		got := s.Parse(c.in)
		if got != c.want {
			t.Errorf("\nin   %s\ngot  %s\nwant %s", c.in, got, c.want)
		}
	}
}

func TestBannedMethodAndEscapes(t *testing.T) {
	s := newServer(t)
	s.N.UpdateOptions(func(o *node.StorageOptions) { o.RPCBanned = "restart" })
	got := s.Parse(`{"jsonrpc":"2.0","method":"restart","params":[],"id":1}`)
	if got != `{"jsonrpc":"2.0","result":[{"result":"banned"}],"id":1}` {
		t.Fatal(got)
	}
	// FPC JSON string escaping: '/' is escaped, non-ASCII becomes \uXXXX.
	if jsonString("a/b\u00e9\n") != `"a\/b\u00E9\n"` {
		t.Fatal(jsonString("a/b\u00e9\n"))
	}
	if jsonString("x\x00y") != `"x\u0000y"` {
		t.Fatal("NUL")
	}
}

func TestHTTPGateAndHost(t *testing.T) {
	s := newServer(t)
	srv := httptest.NewServer(http.HandlerFunc(s.handle))
	defer srv.Close()
	// the test client comes from 127.0.0.1 which is whitelisted by default
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 256)
	n, _ := resp.Body.Read(b)
	resp.Body.Close()
	if !strings.Contains(string(b[:n]), `"code":400`) {
		t.Fatalf("GET must give 400: %s", b[:n])
	}
	if !ValidRPCHost("127.0.0.1,localhost", "127.0.0.1") || ValidRPCHost("127.0.0.1", "10.0.0.1") {
		t.Fatal("whitelist")
	}
	s.N.UpdateOptions(func(o *node.StorageOptions) { o.RPCWhitelist = "10.9.9.9" })
	resp, _ = http.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	n, _ = resp.Body.Read(b)
	resp.Body.Close()
	if !strings.Contains(string(b[:n]), `"code":498`) {
		t.Fatalf("filter: %s", b[:n])
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","method":"getblocksinfo","params":["1","x"],"id":1}`)
	s := newServerFuzz()
	f.Fuzz(func(t *testing.T, in string) { s.Parse(in) })
}
