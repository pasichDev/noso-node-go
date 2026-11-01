package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
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
	// no Save, no merge. A status style command uses it (nosocli status must
	// set it). Everything a writable open would restore or merge is still
	// shown, in memory only.
	ReadOnly bool
}

// MinPassphrase is the shortest passphrase accepted for a NEW encrypted
// wallet (an existing wallet.enc opens with whatever opens it).
const MinPassphrase = 8

// CheckNewPassphrase refuses a short passphrase when opening dataDir would
// create or migrate into a new wallet.enc. It is the one rule shared by every
// front end: nosod, the GUI and nosocli all call it before OpenWalletFor.
func CheckNewPassphrase(dataDir string, pass []byte) error {
	if len(pass) == 0 || len(pass) >= MinPassphrase {
		return nil
	}
	if Exists(filepath.Join(dataDir, "wallet.enc")) || Exists(filepath.Join(dataDir, "wallet.enc.bak")) {
		return nil
	}
	return fmt.Errorf("the wallet passphrase must have at least %d characters", MinPassphrase)
}

// OpenWalletEncrypted opens (or creates) the encrypted wallet next to
// plainPath, writing what it must. The sources are wallet.enc, wallet.enc.bak
// and the legacy wallet.pkw / wallet.pkw.bak; no source is ever erased or
// overwritten by data that lacks its keys:
//
//   - wallet.enc opens: it is the wallet. Keys that only the .bak files hold
//     are added (and saved) with a warning. If wallet.enc does not open but
//     wallet.enc.bak does with this passphrase, wallet.enc is damaged: it is
//     kept as wallet.enc.damaged-<time> and restored from the backup.
//   - wallet.enc is missing: the wallet is the union of wallet.enc.bak (the
//     newest sealed copy) and the verified legacy files, in that order, so a
//     kept wallet.pkw never hides a newer backup. The plain records are sealed
//     byte for byte, the file is read back from disk, decrypted and compared,
//     and every key pair is checked (sign and verify, address). The legacy
//     files stay where they are. A mistyped passphrase therefore costs
//     nothing: move the new wallet.enc away and open again; a backup that
//     does not open is kept under another name by the next save.
//     RetireLegacyWallet removes the plain copies, on explicit request only.
//   - only an unreadable wallet.enc.bak exists: an error (a new wallet would
//     overwrite the backup).
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
	w := &Wallet{path: encPath, pass: append([]byte(nil), pass...), readOnly: o.ReadOnly, plainPath: plainPath}
	bakW := &Wallet{path: encPath + ".bak", pass: w.pass}
	bakOK := Exists(bakW.path) && bakW.LoadErr() == nil
	switch {
	case Exists(encPath):
		if err := w.LoadErr(); err != nil {
			if !bakOK {
				if Exists(plainPath) {
					return nil, fmt.Errorf("%w (wallet.pkw is still present and untouched; if wallet.enc came from a migration with a mistyped passphrase, move it away and start again)", ErrWalletPassphrase)
				}
				return nil, ErrWalletPassphrase
			}
			// the backup opens with this passphrase, so wallet.enc is damaged
			w.arr = nil
			w.mergeRecords(bakW.All())
			w.warn("wallet.enc is damaged; restored from wallet.enc.bak")
			if !o.ReadOnly {
				if err := preserveDamaged(encPath); err != nil {
					return nil, err
				}
				if err := w.SaveErr(); err != nil {
					return nil, err
				}
			}
		}
		if err := w.mergeExtras(plainPath, bakW, bakOK, o.ReadOnly); err != nil {
			return nil, err
		}
	default:
		hasPlain := Exists(plainPath) || Exists(plainPath+".bak")
		switch {
		case bakOK || hasPlain:
			if err := w.restoreOrMigrate(plainPath, bakW, bakOK, o.ReadOnly); err != nil {
				return nil, err
			}
		case Exists(bakW.path):
			return nil, fmt.Errorf("%w (wallet.enc is missing and wallet.enc.bak does not open; not creating a new wallet over it)", ErrWalletPassphrase)
		case o.ReadOnly:
			return w, nil
		default:
			if _, err := w.NewAddress(); err != nil {
				return nil, fmt.Errorf("wallet: cannot write the encrypted wallet: %w", err)
			}
		}
	}
	w.legacyKept = ""
	for _, p := range []string{plainPath, plainPath + ".bak"} {
		if Exists(p) {
			w.legacyKept = plainPath
		}
	}
	if !o.ReadOnly {
		tightenFiles(encPath, encPath+".bak", plainPath, plainPath+".bak")
	}
	return w, nil
}

// legacySource reads a clear-text legacy wallet file for merging or
// migration: the whole records of it, only when every key pair checks out.
//
// warn is a note about a file that is merely unusable (unreadable, no
// records); bad is set when the file holds a record whose keys do not check
// out: migration must stop then, merging into an existing wallet just skips it.
func legacySource(path string) (raw []byte, warn string, bad bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", false
		}
		return nil, fmt.Sprintf("%s cannot be read: %v", filepath.Base(path), err), false
	}
	n := len(b) / types.WalletSize
	if n == 0 {
		return nil, fmt.Sprintf("%s holds no complete record", filepath.Base(path)), false
	}
	rec := b[:n*types.WalletSize]
	if err := verifyKeys(rec); err != nil {
		return nil, fmt.Sprintf("%s ignored: %v", filepath.Base(path), err), true
	}
	return rec, "", false
}

// mergeExtras adds keys that wallet.enc lacks but wallet.enc.bak or the
// verified legacy files hold, and saves them.
func (w *Wallet) mergeExtras(plainPath string, bakW *Wallet, bakOK, readOnly bool) error {
	n := 0
	if bakOK {
		n += w.mergeRecords(bakW.All())
	}
	for _, p := range []string{plainPath, plainPath + ".bak"} {
		raw, warn, _ := legacySource(p)
		if warn != "" {
			w.warn(warn)
		}
		recs, _ := splitRecords(raw)
		n += w.mergeRecords(recs)
	}
	if n == 0 {
		return nil
	}
	w.warn(fmt.Sprintf("%d key(s) that wallet.enc lacked were recovered from the backup files", n))
	if readOnly {
		return nil
	}
	return w.SaveErr()
}

// restoreOrMigrate builds the wallet from the sources when wallet.enc is
// missing (see OpenWalletEncrypted).
func (w *Wallet) restoreOrMigrate(plainPath string, bakW *Wallet, bakOK, readOnly bool) error {
	var records []byte // byte exact for the first source, then only new addresses
	have := map[string]bool{}
	add := func(raw []byte) {
		recs, _ := splitRecords(raw)
		if len(records) == 0 {
			records = append(records, raw...)
			for _, r := range recs {
				have[r.Hash] = true
			}
			return
		}
		for _, r := range recs {
			if !have[r.Hash] {
				have[r.Hash] = true
				records = append(records, r.Encode()...)
			}
		}
	}
	if bakOK {
		var b []byte
		for _, r := range bakW.All() {
			b = append(b, r.Encode()...)
		}
		add(b)
	}
	legacyErr := ""
	for _, p := range []string{plainPath, plainPath + ".bak"} {
		raw, warn, bad := legacySource(p)
		if bad {
			return fmt.Errorf("wallet: legacy wallet.pkw not migrated, wallet files kept: %s", warn)
		}
		if warn != "" {
			w.warn(warn)
			legacyErr = warn
		}
		if raw != nil {
			add(raw)
		}
	}
	if len(records) == 0 {
		if Exists(plainPath) {
			return fmt.Errorf("wallet: legacy wallet.pkw not migrated, wallet.pkw kept: %s", legacyErr)
		}
		return errors.New("wallet: no usable wallet source")
	}
	if readOnly {
		recs, _ := splitRecords(records)
		w.mergeRecords(recs)
		return nil
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
		return errors.New("wallet: migration check failed; the old wallet files were kept")
	}
	if !w.Load() || w.Len() == 0 {
		_ = os.Remove(w.path)
		return errors.New("wallet: migration check failed; the old wallet files were kept")
	}
	if bakOK {
		w.warn("wallet.enc was missing; restored from wallet.enc.bak and the legacy files")
	}
	return nil
}

// OpenWalletFor chooses the wallet the way the front ends must: with
// insecurePlain the clear-text wallet.pkw is used as it is (the passphrase is
// ignored, nothing is migrated), and it is refused when a wallet.enc or a
// wallet.enc.bak exists so a second, empty wallet is never started silently.
// Otherwise the encrypted wallet needs a passphrase.
func OpenWalletFor(plainPath string, pass []byte, insecurePlain bool, o WalletOpenOptions) (*Wallet, error) {
	if insecurePlain {
		dir := filepath.Dir(plainPath)
		for _, n := range []string{"wallet.enc", "wallet.enc.bak"} {
			if Exists(filepath.Join(dir, n)) {
				return nil, fmt.Errorf("wallet: %s exists; refusing -insecure-plain-wallet (it would start a different, empty wallet)", n)
			}
		}
		return openWalletPlain(plainPath, o.ReadOnly)
	}
	return OpenWalletEncryptedOpts(plainPath, pass, o)
}

// LegacyKept returns the path of a wallet.pkw (or its .bak) that is still on
// disk next to wallet.enc, "" otherwise. Clear-text keys stay readable there
// until RetireLegacy runs.
func (w *Wallet) LegacyKept() string { return w.legacyKept }

// LegacyWarning is the text a front end prints at every start while clear-text
// legacy wallet files remain ("" when none): see RetireLegacy.
func (w *Wallet) LegacyWarning() string {
	if w.legacyKept == "" {
		return ""
	}
	return "WARNING: " + w.legacyKept + " (and its .bak) still hold your private keys in clear text. " +
		"Once wallet.enc is verified, remove them with: nosocli wallet retire-legacy"
}

// RetireLegacy is RetireLegacyWallet for this wallet's own files and
// passphrase; the CLI command `wallet retire-legacy` calls it.
func (w *Wallet) RetireLegacy() error {
	if w.readOnly {
		return ErrWalletReadOnly
	}
	if w.plainPath == "" || len(w.pass) == 0 {
		return errors.New("wallet: not an encrypted wallet")
	}
	if err := RetireLegacyWallet(w.plainPath, w.pass); err != nil {
		return err
	}
	w.legacyKept = ""
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

// RetireLegacyWallet removes the clear-text wallet.pkw, wallet.pkw.bak and
// wallet.pkw.tmp after the caller explicitly asked for it. It first decrypts
// wallet.enc with pass and checks that every record of every one of those
// files is in it with the same private key; if any file holds a key that
// wallet.enc lacks, everything stays and an error names the file. Files are
// overwritten with zeros, synced and removed; a file that could not be
// overwritten or removed is reported and left in place. Nothing calls this
// automatically (Wallet.RetireLegacy is the CLI entry point).
func RetireLegacyWallet(plainPath string, pass []byte) error {
	encPath := filepath.Join(filepath.Dir(plainPath), "wallet.enc")
	disk, err := os.ReadFile(encPath)
	if err != nil {
		return err
	}
	back, err := openWallet(disk, pass)
	if err != nil {
		return err
	}
	if err := verifyKeys(back); err != nil {
		return err
	}
	inEnc := map[string]string{}
	for i := 0; i+types.WalletSize <= len(back); i += types.WalletSize {
		r := types.DecodeWallet(back[i:])
		inEnc[r.Hash] = r.PrivateKey
	}
	var targets []string
	for _, p := range []string{plainPath, plainPath + ".bak", plainPath + ".tmp"} {
		raw, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if p == plainPath && len(raw)/types.WalletSize == 0 {
			return errors.New("wallet: wallet.pkw holds no records; nothing removed")
		}
		recs, _ := splitRecords(raw)
		for _, r := range recs {
			if k, ok := inEnc[r.Hash]; !ok || k != r.PrivateKey {
				return fmt.Errorf("wallet: %s holds a key (%s) that wallet.enc does not; nothing removed", filepath.Base(p), r.Hash)
			}
		}
		targets = append(targets, p)
	}
	if len(targets) == 0 {
		return errors.New("wallet: no legacy wallet files to remove")
	}
	var errs []error
	for _, p := range targets {
		if err := shred(p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(p), err))
		}
	}
	return errors.Join(errs...)
}

// shred overwrites a file with zeros, syncs and removes it (best effort on
// flash storage and journalled filesystems, see docs/compatibility.md). It
// reports a failure at any step and removes the file only after a successful
// overwrite.
func shred(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write(make([]byte, st.Size()))
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	return os.Remove(path)
}
