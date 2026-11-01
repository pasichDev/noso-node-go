package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// C-08: nothing in the interpreter can download or run code.
func TestC08_NoUpdateCommands(t *testing.T) {
	d := newDispatcher(t)
	for _, c := range []string{"update", "getbeta", "checkupdates", "sendreport", "testnet 5", "UPDATE 0.4.5 /or"} {
		out := strings.Join(d.Run(c), "\n")
		if !strings.HasPrefix(out, "Unknown command") {
			t.Fatalf("C-08: %q is still a command: %q", c, out)
		}
	}
	for name := range handlers {
		if strings.Contains(name, "UPDATE") || strings.Contains(name, "BETA") {
			t.Fatalf("handler %s", name)
		}
	}
}

// H-10: key commands are never echoed or logged.
func TestH10_SensitiveCommands(t *testing.T) {
	d := newDispatcher(t)
	d.Echo = true
	addr := d.N.Wallet.At(0).Hash
	out := d.Run("showkeys " + addr)
	for _, l := range out {
		if strings.HasPrefix(l, ">>") {
			t.Fatal("key command echoed")
		}
	}
	for _, c := range []string{"showkeys x", "expkeys x", "newfromkeys a b", "signcfg 1", "directive 1 2 x"} {
		if !Sensitive(c) {
			t.Fatalf("%s must be sensitive", c)
		}
	}
	if Sensitive("balance") {
		t.Fatal("balance flagged")
	}
}

// M-02: a seed list is used only when its signature verifies under the
// configured release key, over https.
func TestM02_SignedSeedList(t *testing.T) {
	kp := crypto.GenerateKeyPair()
	list := "1.2.3.4;8080:5.6.7.8;8080:"
	mux := http.NewServeMux()
	mux.HandleFunc("/defseeds.nos", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(list)) })
	mux.HandleFunc("/defseeds.nos.sig", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(crypto.SignCanonical(kp.PrivateKey, "SEEDS1", list)))
	})
	mux.HandleFunc("/bad.nos", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("9.9.9.9;8080:")) })
	mux.HandleFunc("/bad.nos.sig", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(crypto.SignCanonical(kp.PrivateKey, "SEEDS1", list)))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	old := seedHTTPClient
	seedHTTPClient = srv.Client()
	defer func() { seedHTTPClient = old }()
	if got := FetchSeeds(srv.URL+"/defseeds.nos", kp.PublicKey); got != list {
		t.Fatalf("signed list refused: %q", got)
	}
	if FetchSeeds(srv.URL+"/bad.nos", kp.PublicKey) != "" {
		t.Fatal("list with a signature for other content accepted")
	}
	if FetchSeeds(srv.URL+"/defseeds.nos", "") != "" {
		t.Fatal("list accepted without a configured key")
	}
	if FetchSeeds(srv.URL+"/defseeds.nos", crypto.GenerateKeyPair().PublicKey) != "" {
		t.Fatal("list accepted under the wrong key")
	}
	if FetchSeeds("http://example.invalid/defseeds.nos", kp.PublicKey) != "" {
		t.Fatal("plain http accepted")
	}
	// an untrusted certificate is refused by the default client
	seedHTTPClient = &http.Client{}
	if FetchSeeds(srv.URL+"/defseeds.nos", kp.PublicKey) != "" {
		t.Fatal("M-02: unverified TLS certificate accepted")
	}
}
