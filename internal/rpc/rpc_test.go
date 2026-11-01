package rpc

import (
	"io"
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

func post(t *testing.T, url, token, body string, hdr map[string]string) string {
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }() // test cleanup
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// FIX(H-09): tokens, scopes, Origin ban, content type, no private keys.
func TestH09_RPCAccessControl(t *testing.T) {
	s := newServer(t)
	s.N.UpdateOptions(func(o *node.StorageOptions) { o.RPCToken = "read-token"; o.RPCSpendToken = "spend-token" })
	srv := httptest.NewServer(http.HandlerFunc(s.handle))
	defer srv.Close()
	call := `{"jsonrpc":"2.0","method":"test","params":[],"id":1}`
	if got := post(t, srv.URL, "", call, nil); !strings.Contains(got, `"code":498`) {
		t.Fatalf("no token accepted: %s", got)
	}
	if got := post(t, srv.URL, "wrong", call, nil); !strings.Contains(got, `"code":498`) {
		t.Fatalf("wrong token accepted: %s", got)
	}
	if got := post(t, srv.URL, "read-token", call, nil); !strings.Contains(got, "testok") {
		t.Fatalf("valid token refused: %s", got)
	}
	// a web page cannot call the node: browsers always add Origin
	if got := post(t, srv.URL, "read-token", call, map[string]string{"Origin": "https://evil.example"}); !strings.Contains(got, `"code":498`) {
		t.Fatalf("cross-origin request accepted: %s", got)
	}
	// form posts (the CSRF vector) are not JSON
	if got := post(t, srv.URL, "read-token", call, map[string]string{"Content-Type": "text/plain"}); !strings.Contains(got, `"code":400`) {
		t.Fatalf("non-JSON content type accepted: %s", got)
	}
	// scopes
	spend := `{"jsonrpc":"2.0","method":"getnewaddressfull","params":[],"id":2}`
	if got := post(t, srv.URL, "read-token", spend, nil); !strings.Contains(got, `"code":498`) {
		t.Fatalf("read token reached a spend method: %s", got)
	}
	got := post(t, srv.URL, "spend-token", spend, nil)
	if !strings.Contains(got, `"hash":"N`) || !strings.Contains(got, `"private":""`) {
		t.Fatalf("private key returned or call failed: %s", got)
	}
	// empty tokens never match an empty header
	s.N.UpdateOptions(func(o *node.StorageOptions) { o.RPCToken = ""; o.RPCSpendToken = "" })
	if got := post(t, srv.URL, "", call, nil); !strings.Contains(got, `"code":498`) {
		t.Fatalf("empty tokens grant access: %s", got)
	}
}

func TestH09_LoopbackBindAndHostFilter(t *testing.T) {
	s := newServer(t)
	if err := s.Start(0); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Fatalf("RPC listens on %s", s.Addr())
	}
	if !ValidRPCHost("127.0.0.1,localhost", "127.0.0.1") || ValidRPCHost("127.0.0.1", "10.0.0.1") {
		t.Fatal("whitelist")
	}
	s.N.UpdateOptions(func(o *node.StorageOptions) { o.RPCToken = "t"; o.RPCWhitelist = "10.9.9.9" })
	if got := post(t, "http://"+s.Addr(), "t", `{"jsonrpc":"2.0","method":"test","params":[],"id":1}`, nil); !strings.Contains(got, `"code":498`) {
		t.Fatalf("host filter: %s", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","method":"getblocksinfo","params":["1","x"],"id":1}`)
	s := newServerFuzz()
	f.Fuzz(func(t *testing.T, in string) { s.Parse(in) })
}

// getmainnetinfo with no consensus (a single node, or seeds that have not
// agreed) answers with the node's own view instead of error 499.
func TestMainnetInfoWithoutConsensus(t *testing.T) {
	s := newServer(t)
	got := s.Parse(`{"jsonrpc":"2.0","method":"getmainnetinfo","params":[],"id":5}`)
	if strings.Contains(got, `"error"`) || !strings.Contains(got, `"lastblock"`) || !strings.Contains(got, `"supply"`) {
		t.Fatalf("getmainnetinfo without consensus: %s", got)
	}
}
