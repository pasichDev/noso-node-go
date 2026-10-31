package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
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

// WalletOpenOptions selects what opening an encrypted wallet may change on
// disk.
type WalletOpenOptions struct {
	// ReadOnly opens without writing anything: no migration, no new wallet,
	// no Save. A status style command uses it. A wallet.pkw is then read in
	// memory only.
	ReadOnly bool
}

// OpenWalletEncrypted opens (or creates) the encrypted wallet next to
// plainPath, writing what it must:
//
//   - wallet.enc exists: it is decrypted; nothing else is touched.
//   - only a legacy wallet.pkw exists: it is migrated, never destroyed.
//     The plain records are sealed byte for byte, the file is read back from
//     disk, decrypted and compared with the original, and every key pair is
//     checked (sign and verify, address). wallet.pkw and its .bak stay where
//     they are. A mistyped passphrase therefore costs nothing: remove the
//     new wallet.enc and migrate again. RetireLegacyWallet removes the plain
//     copy, on explicit request only.
//   - neither exists but wallet.enc.bak does: the backup is restored if the
//     passphrase opens it, otherwise an error (a new wallet would overwrite
//     the backup).
//   - nothing exists: a new wallet with one fresh address.
func OpenWalletEncrypted(plainPath string, pass []byte) (*Wallet, error) {
	return OpenWalletEncryptedOpts(plainPath, pass, WalletOpenOptions{})
}

// OpenWalletEncryptedOpts is OpenWalletEncrypted with options.
func OpenWalletEncryptedOpts(plainPath string, pass []byte, o WalletOpenOptions) (*Wallet, error) {
	if len(pass) == 0 {
		return nil, errors.New("wallet: empty passphrase")
	}
	encPath := filepath.Join(filepath.Dir(plainPath), "wallet.enc")
	w := &Wallet{path: encPath, pass: append([]byte(nil), pass...), readOnly: o.ReadOnly}
	switch {
	case Exists(encPath):
		if !w.Load() {
			if Exists(plainPath) {
				return nil, fmt.Errorf("%w (wallet.pkw is still present and untouched; if wallet.enc came from a migration with a mistyped passphrase, move it away and start again)", ErrWalletPassphrase)
			}
			return nil, ErrWalletPassphrase
		}
	case Exists(plainPath):
		if o.ReadOnly {
			legacy, _ := OpenWallet(plainPath)
			legacy.readOnly = true
			return legacy, nil
		}
		if err := migrateLegacy(w, plainPath); err != nil {
			return nil, err
		}
	case Exists(encPath + ".bak"):
		bak := &Wallet{path: encPath + ".bak", pass: w.pass}
		if !bak.Load() {
			return nil, fmt.Errorf("%w (wallet.enc is missing and wallet.enc.bak does not open; not creating a new wallet over it)", ErrWalletPassphrase)
		}
		if o.ReadOnly {
			bak.readOnly = true
			return bak, nil
		}
		for _, r := range bak.All() {
			w.Insert(r)
		}
		if err := w.SaveErr(); err != nil {
			return nil, err
		}
	default:
		if o.ReadOnly {
			return w, nil
		}
		if _, err := w.NewAddress(); err != nil {
			return nil, errors.New("wallet: cannot write the encrypted wallet")
		}
	}
	if !o.ReadOnly {
		_ = os.Chmod(encPath, 0o600)
	}
	return w, nil
}

// OpenWalletFor chooses the wallet the way the front ends must: with
// insecurePlain the clear-text wallet.pkw is used as it is (the passphrase is
// ignored, nothing is migrated), and it is refused when a wallet.enc exists
// so a second, empty wallet is never started silently. Otherwise the
// encrypted wallet needs a passphrase.
func OpenWalletFor(plainPath string, pass []byte, insecurePlain bool, o WalletOpenOptions) (*Wallet, error) {
	if insecurePlain {
		if Exists(filepath.Join(filepath.Dir(plainPath), "wallet.enc")) {
			return nil, errors.New("wallet: wallet.enc exists; refusing -insecure-plain-wallet (it would start a different, empty wallet)")
		}
		if o.ReadOnly {
			if !Exists(plainPath) {
				return &Wallet{path: plainPath, readOnly: true}, nil
			}
			w, _ := OpenWallet(plainPath)
			w.readOnly = true
			return w, nil
		}
		w, _ := OpenWallet(plainPath)
		return w, nil
	}
	return OpenWalletEncryptedOpts(plainPath, pass, o)
}

// LegacyKept returns the path of a wallet.pkw that was migrated and is still
// on disk ("" otherwise): the front end should tell the user.
func (w *Wallet) LegacyKept() string { return w.legacyKept }

// migrateLegacy seals plainPath into w.path without removing anything.
func migrateLegacy(w *Wallet, plainPath string) error {
	raw, err := os.ReadFile(plainPath)
	if err != nil {
		return err
	}
	n := len(raw) / types.WalletSize
	if n == 0 {
		return errors.New("wallet: legacy wallet.pkw holds no addresses")
	}
	records := raw[:n*types.WalletSize]
	if err := verifyKeys(records); err != nil {
		return fmt.Errorf("wallet: legacy wallet.pkw not migrated, wallet.pkw kept: %w", err)
	}
	sealed, err := sealWallet(records, w.pass)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(w.path, sealed); err != nil {
		return fmt.Errorf("wallet: cannot write the encrypted wallet: %w", err)
	}
	// full round trip from disk
	disk, err := os.ReadFile(w.path)
	var back []byte
	if err == nil {
		back, err = openWallet(disk, w.pass)
	}
	if err != nil || !bytes.Equal(back, records) || verifyKeys(back) != nil {
		_ = os.Remove(w.path) // our own file, never the original
		return errors.New("wallet: migration check failed; wallet.pkw kept")
	}
	if !w.Load() || w.Len() == 0 {
		_ = os.Remove(w.path)
		return errors.New("wallet: migration check failed; wallet.pkw kept")
	}
	w.legacyKept = plainPath
	return nil
}

// verifyKeys checks every record that has a private key: the key pair signs
// and verifies, and the address derives from the public key. Records without
// a private key (watch-only) are skipped.
func verifyKeys(records []byte) error {
	for i := 0; i+types.WalletSize <= len(records); i += types.WalletSize {
		r := types.DecodeWallet(records[i:])
		if r.PrivateKey == "" {
			continue
		}
		sig := crypto.SignCanonical(r.PrivateKey, "wallet-verify", "x")
		if sig == "" || !crypto.VerifyCanonical(r.PublicKey, sig, "wallet-verify", "x") {
			return fmt.Errorf("record %d (%s): private key does not match public key", i/types.WalletSize, r.Hash)
		}
		if r.Hash != crypto.GetAddressFromPublicKey(r.PublicKey, 0) && r.Hash != crypto.GetAddressFromPublicKey(r.PublicKey, 1) {
			return fmt.Errorf("record %d (%s): address does not derive from the public key", i/types.WalletSize, r.Hash)
		}
	}
	return nil
}

// RetireLegacyWallet removes the clear-text wallet.pkw (and .bak) after the
// caller explicitly asked for it. It first decrypts wallet.enc with pass and
// checks that every record of wallet.pkw is byte-identical in it; anything
// else leaves all files in place and returns an error. Nothing calls this
// automatically.
func RetireLegacyWallet(plainPath string, pass []byte) error {
	encPath := filepath.Join(filepath.Dir(plainPath), "wallet.enc")
	plain, err := os.ReadFile(plainPath)
	if err != nil {
		return err
	}
	disk, err := os.ReadFile(encPath)
	if err != nil {
		return err
	}
	back, err := openWallet(disk, pass)
	if err != nil {
		return err
	}
	n := len(plain) / types.WalletSize
	if n == 0 {
		return errors.New("wallet: wallet.pkw holds no records; nothing removed")
	}
	inEnc := map[string]string{}
	for i := 0; i+types.WalletSize <= len(back); i += types.WalletSize {
		r := types.DecodeWallet(back[i:])
		inEnc[r.Hash] = r.PrivateKey
	}
	for i := 0; i < n; i++ {
		r := types.DecodeWallet(plain[i*types.WalletSize:])
		if k, ok := inEnc[r.Hash]; !ok || k != r.PrivateKey {
			return errors.New("wallet: wallet.enc does not hold every key of wallet.pkw; nothing removed")
		}
	}
	if err := verifyKeys(back); err != nil {
		return err
	}
	for _, p := range []string{plainPath, plainPath + ".bak"} {
		shred(p)
	}
	return nil
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
