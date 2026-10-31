package crypto

import "testing"

func TestRIPEMD160Vectors(t *testing.T) {
	// Official test vectors from the RIPEMD-160 specification.
	cases := map[string]string{
		"":                           "9C1185A5C5E9FC54612808977EE8F548B2258D31",
		"a":                          "0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE",
		"abc":                        "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC",
		"message digest":             "5D0689EF49D2FAE572B881B123A85FFA21595F36",
		"abcdefghijklmnopqrstuvwxyz": "F71C27109C692C1B56BBDCEB5B9D2865B3708DBC",
	}
	for in, want := range cases {
		if got := RIPEMD160String(in); got != want {
			t.Errorf("RIPEMD160(%q)=%s want %s", in, got, want)
		}
	}
}
