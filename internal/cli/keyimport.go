package cli

import (
	"errors"
	"io"
	"os"
	"strings"
)

// PrepareKeyImport turns the command line of `nosocli newfromkeys` into the
// line the node runs. FIX(F-17): the private key used to be the last word of
// the command, so it sat in the process arguments (visible to every user in
// `ps`) and in the shell history. Now the line is `newfromkeys <public key>
// <file>` or `newfromkeys <public key> -`: the private key is read from the
// file, or from stdin for `-`, and put into the line only after that. A third
// word that is not a readable file is refused, never used as the key. Any
// other command is returned unchanged. stdin may be nil (an interactive
// session, whose standard input carries the commands themselves).
func PrepareKeyImport(line string, stdin io.Reader) (string, error) {
	f := strings.Fields(line)
	if len(f) == 0 || !strings.EqualFold(f[0], "newfromkeys") {
		return line, nil
	}
	const usage = "usage: newfromkeys <public key> <file with the private key>  (or - to read it from standard input); the private key is never taken from the command line"
	if len(f) != 3 {
		return "", errors.New(usage)
	}
	var src io.Reader
	if f[2] == "-" {
		if stdin == nil {
			return "", errors.New("standard input is not available here; give a file")
		}
		src = stdin
	} else {
		fh, err := os.Open(f[2])
		if err != nil {
			return "", errors.New(usage)
		}
		defer func() { _ = fh.Close() }() // read only
		src = fh
	}
	raw, err := io.ReadAll(io.LimitReader(src, 4096))
	if err != nil {
		return "", err
	}
	priv := strings.TrimSpace(string(raw))
	if priv == "" || strings.ContainsAny(priv, " \t\r\n") {
		return "", errors.New("the key file must hold the private key alone, on one line")
	}
	return f[0] + " " + f[1] + " " + priv, nil
}
