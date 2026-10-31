# Cryptography

## Hashes

* `HashSha256String`, `HashMD160String`, `HashMD5String` return **upper-case
  hex**. The input is the string bytes.
* The address of a public key is computed from the **Base64 text** of the key,
  not from its bytes: `SHA256(text)` -> upper-case hex -> `RIPEMD160(thatHexText)`
  -> upper-case hex -> big number -> Base58 body; the checksum is the decimal
  sum of the body's alphabet indices, itself written in Base58. The address is
  `N` + body + checksum (`M` for multi-signature). Checked against the
  developer key in the source (`AdminPubKey` -> `N3DthVsfEUtqrgWFHTEB6F88xLkT3Df`).
* `IsValidHashAddress`: length above 20, first letter `N` or `M`, body
  all Base58, and `first + body + B58(sum)` equals the address. The body is
  `copy(addr,2,len-3)`, so the checksum must be exactly 2 characters.

## Base conversions

* Base58 uses the Bitcoin alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.
* Base36 uses lower-case `0-9a-z`.
* COMPAT: `B16ToB58` (used by transfer hashes `tR...`) builds a CryptoLib
  `TBigInteger` from the bytes with the **signed** constructor. A hash whose
  top bit is set is negative, and the "unsigned byte array" of a negative
  number is its minimal two's complement encoding, which drops leading 0xFF
  bytes. The port reproduces this (`bigFromSignedBytes`,
  `bigToByteArrayUnsigned`).
* `B16ToB36` (order hashes `OR...`) is a plain unsigned conversion without
  leading zero digits; an all-zero input gives one `0` per zero byte.
* `OrderHash = "OR" + B16ToB36(SHA256(text))`;
  `TransferHash = "tR" + B58(hash) + B58(checksum)`.

## Base64

Keys and signatures are standard Base64 with padding. COMPAT: before signing
or verifying, the *message* is also run through the lenient Free Pascal
Base64 decoder (`DecodeStringBase64(message)`), so the signed bytes are the
decoded remains of the plain text (all non-Base64 characters dropped). The
port implements the documented MIME-mode behaviour (skip characters outside
the alphabet, stop at `=`); this could not be compared against the FPC
runtime.

## Signatures

secp256k1, SHA-1 digest of the (decoded) message, ECDSA with random `k`,
DER encoded, Base64 text (BouncyCastle `SHA-1withECDSA` via CryptoLib4Pascal).
Verification accepts any valid DER signature, including high-S values.
Public key = Base64 of the uncompressed point (65 bytes, 88 characters);
compressed and hybrid encodings are accepted on verification. Private key =
Base64 of the minimal big-endian scalar (no zero padding to 32 bytes).

## Certificates

`GetCertificate`: sign `OWN + address + time`, build
`OWN:pubkey:time:signature`, XOR with the key `SHA256("noso")` (hex text),
upper-case, prefix `1`, Base58, plus a 3 character checksum
(`B58(sum of indices + length)`, left padded with `1`). `CheckCertificate`
reverses it.

## Multi-signature addresses

`getmulti needed,total addr1,addr2,...` builds the key
`needed,total:addr1,addr2,...` (addresses sorted) and derives an `M` address
from it. COMPAT: the original sorting loop evaluates its bound once while
inserting, which can duplicate entries; the port keeps the same loop, so some
orders of input fail with "Wrong addresses count".

## Changes from the original (security fixes)

* Signatures: `SignCanonical` / `VerifyCanonical` hash a length-prefixed
  message (`"NOSO-SIG-v1"`, chain id, domain, fields) with SHA-256 and sign it
  with ECDSA on secp256k1. S is normalised to the low half and high-S
  signatures are rejected. The lenient Base64 decoding of messages, the SHA-1
  digest and the plain concatenated signed text of the original no longer
  exist (findings H-07, H-08, M-13).
* Identity hashes of files and states (`IDHash`) are the first 128 bits of
  SHA-256 (32 hex characters), replacing MD5 in the same fields (M-13). The
  real MD5 is only available through the `md5` console command.
* Certificates (`GetCertificate`/`CheckCertificate`) have the form
  `C2:pubkey:time:audience:nonce:signature`; the verifier supplies audience
  and nonce, and the XOR layer is gone (L-05).
* Address derivation, `tR...`/`OR...` hash formats and Base58/Base36
  conversions are unchanged.
