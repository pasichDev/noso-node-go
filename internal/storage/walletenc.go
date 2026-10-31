package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// Encrypted wallet file (FIX(H-10)). The original keeps private keys as
// plain text records in wallet.pkw (nosowallcon.pas:278-306).
//
//	"NOSOWLT1" | argon2id time(u32) memKiB(u32) threads(u8) | salt(16) |
//	nonce(12) | AES-256-GCM(records)   (header bytes are the AAD)
const (
	walletMagic   = "NOSOWLT1"
	argonTime     = 3
	argonMemKiB   = 64 * 1024
	argonThreads  = 4
	walletHdrSize = len(walletMagic) + 4 + 4 + 1 + 16 + 12
)

// ErrWalletPassphrase is returned for a wrong passphrase or a damaged file.
var ErrWalletPassphrase = errors.New("wallet: wrong passphrase or damaged file")

func deriveKey(pass, salt []byte, t, m uint32, th uint8) []byte {
	return argon2.IDKey(pass, salt, t, m, th, 32)
}

func sealWallet(plain, pass []byte) ([]byte, error) {
	hdr := make([]byte, walletHdrSize)
	copy(hdr, walletMagic)
	o := len(walletMagic)
	binary.BigEndian.PutUint32(hdr[o:], argonTime)
	binary.BigEndian.PutUint32(hdr[o+4:], argonMemKiB)
	hdr[o+8] = argonThreads
	if _, err := rand.Read(hdr[o+9 : o+25]); err != nil { // salt
		return nil, err
	}
	if _, err := rand.Read(hdr[o+25 : o+37]); err != nil { // nonce
		return nil, err
	}
	key := deriveKey(pass, hdr[o+9:o+25], argonTime, argonMemKiB, argonThreads)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return append(hdr, g.Seal(nil, hdr[o+25:o+37], plain, hdr[:o+25])...), nil
}

func openWallet(raw, pass []byte) ([]byte, error) {
	o := len(walletMagic)
	if len(raw) < walletHdrSize+16 || string(raw[:o]) != walletMagic {
		return nil, ErrWalletPassphrase
	}
	t := binary.BigEndian.Uint32(raw[o:])
	m := binary.BigEndian.Uint32(raw[o+4:])
	th := raw[o+8]
	if t == 0 || t > 20 || m < 8 || m > 1<<21 || th == 0 { // bound a hostile header
		return nil, ErrWalletPassphrase
	}
	key := deriveKey(pass, raw[o+9:o+25], t, m, th)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	plain, err := g.Open(nil, raw[o+25:o+37], raw[walletHdrSize:], raw[:o+25])
	if err != nil {
		return nil, ErrWalletPassphrase
	}
	return plain, nil
}

// OpenWalletEncrypted opens (or creates) the encrypted wallet next to
// plainPath. If an encrypted file exists it is decrypted. Otherwise a
// legacy plaintext wallet.pkw is migrated: its records are written to the
// encrypted file, the plaintext file and its backup are overwritten with
// zeros and deleted. A brand new wallet gets one fresh address.
func OpenWalletEncrypted(plainPath string, pass []byte) (*Wallet, error) {
	if len(pass) == 0 {
		return nil, errors.New("wallet: empty passphrase")
	}
	encPath := filepath.Join(filepath.Dir(plainPath), "wallet.enc")
	w := &Wallet{path: encPath, pass: append([]byte(nil), pass...)}
	switch {
	case Exists(encPath):
		if !w.Load() {
			return nil, ErrWalletPassphrase
		}
	case Exists(plainPath):
		legacy, _ := OpenWallet(plainPath)
		for _, r := range legacy.All() {
			w.Insert(r)
		}
		if w.Len() == 0 {
			return nil, errors.New("wallet: legacy wallet.pkw holds no addresses")
		}
		if !w.Save() {
			return nil, errors.New("wallet: cannot write the encrypted wallet")
		}
		// verify before destroying the original
		check := &Wallet{path: encPath, pass: w.pass}
		if !check.Load() || check.Len() != w.Len() {
			return nil, errors.New("wallet: migration check failed; plaintext wallet kept")
		}
		for _, p := range []string{plainPath, plainPath + ".bak"} {
			shred(p)
		}
	default:
		kp := crypto.GenerateKeyPair()
		var nw = newWalletRecord(kp)
		w.Insert(nw)
		if !w.Save() {
			return nil, errors.New("wallet: cannot write the encrypted wallet")
		}
	}
	_ = os.Chmod(encPath, 0o600)
	return w, nil
}

// shred overwrites a file with zeros and removes it (best effort; flash
// storage and journals may keep copies, see docs/compatibility.md).
func shred(path string) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		_, _ = f.Write(make([]byte, st.Size()))
		_ = f.Sync()
		_ = f.Close()
	}
	_ = os.Remove(path)
}
