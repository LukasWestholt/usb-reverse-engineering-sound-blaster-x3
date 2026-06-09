#!/usr/bin/env python3
"""
Verify the AES-256-GCM handshake implementation against a known
challenge-response pair captured from the Creative app startup.

This script requires the key extracted from your own copy of CTCDC.dll.
Set it via the SB_CTCDC_KEY environment variable (64 hex chars, 32 bytes):

  export SB_CTCDC_KEY=<64 hex chars from 0x101d9a74-0x101d9a93 in CTCDC.dll>
  uv run python scripts/test_crypto.py

Extraction (Ghidra): open CTCDC.dll, press G, go to 101d9a74, read 32 bytes.
"""
import hashlib
import hmac
import os
import sys

# ── key: loaded from environment, NOT hardcoded ────────────────────────────────
_hex_key = os.environ.get("SB_CTCDC_KEY", "").strip()
if not _hex_key:
    print("SB_CTCDC_KEY not set. See script docstring for extraction instructions.")
    sys.exit(1)
KEY_LE = bytes.fromhex(_hex_key)
if len(KEY_LE) != 32:
    print(f"SB_CTCDC_KEY must be 32 bytes (64 hex chars), got {len(KEY_LE)}")
    sys.exit(1)

# same bytes with each 4-byte word byte-reversed (big-endian interpretation)
KEY_BE = b"".join(KEY_LE[i : i + 4][::-1] for i in range(0, len(KEY_LE), 4))

# ── captured challenge/response (capture-app-startup-2.pcapng) ────────────────
NONCE = bytes.fromhex(
    "1e046432"  # fixed 4-byte header (always the same)
    "fa81dc0d68fa262bee51538c93385a28ac75600b407e63fa43be9f6f4ca6f919"
)  # 36 bytes total

RESPONSE = bytes.fromhex(
    "6987721088d8aa20693caecb85d46273041fd1c1c918141e9109dae97647e76ac"
    "67aecdee05a64fb129eb74baa3bed4ed93026cd81540eb5d2a4e6aa751d27b3"
)  # 64 bytes total (response to "unlock" command, before \r\n)

FOUND: list[str] = []


def check(label: str, result: bytes) -> bool:
    n = len(result)
    expected = RESPONSE[:n]
    ok = result == expected
    if ok:
        FOUND.append(label)
        print(f"  *** MATCH ***  {label}")
        print(f"    result:   {result.hex()}")
    else:
        print(f"  no match   {label}")
    return ok


def run_hmac_tests() -> None:
    print("\n-- HMAC tests ---------------------------------------------------")
    for key_label, key in [("key_le", KEY_LE), ("key_be", KEY_BE)]:
        for msg_label, msg in [
            ("nonce_full_36", NONCE),
            ("nonce_random_32", NONCE[4:]),  # skip fixed 4-byte header
            ("nonce_header_4", NONCE[:4]),
        ]:
            for algo_name, algo in [
                ("SHA512", hashlib.sha512),
                ("SHA256", hashlib.sha256),
                ("SHA384", hashlib.sha384),
                ("SHA1", hashlib.sha1),
                ("MD5", hashlib.md5),
            ]:
                result = hmac.new(key=key, msg=msg, digestmod=algo).digest()
                check(f"HMAC-{algo_name}({key_label}, {msg_label})", result)


def run_aes_tests() -> None:
    print("\n-- AES tests ----------------------------------------------------")
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        print("  pycryptodome not installed. Run: uv add pycryptodome")
        return

    # Hypothesis: response = random_IV(16) || AES-256-CBC(key, IV, nonce_padded)
    # The 16 random bytes the DLL generates become the IV, prepended to the ciphertext.
    # Device decrypts, checks the inner nonce matches what it sent.
    for key_label, key in [("key_le", KEY_LE), ("key_be", KEY_BE)]:
        iv = RESPONSE[:16]
        ct = RESPONSE[16:]  # 48 bytes

        # Decrypt and see if nonce is recoverable
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        nonce_match = pt[:36] == NONCE
        print(f"  AES-256-CBC DECRYPT ({key_label}, iv=resp[0:16], ct=resp[16:64]):")
        print(f"    plaintext hex: {pt.hex()}")
        if NONCE in pt:
            print(f"    *** NONCE FOUND IN PLAINTEXT! ***")
            FOUND.append(f"AES-256-CBC-decrypt({key_label})")
        elif pt[:36] == NONCE:
            print(f"    *** NONCE IS FIRST 36 BYTES OF PLAINTEXT! ***")
            FOUND.append(f"AES-256-CBC-decrypt({key_label})")

        # Encrypt: try various nonce paddings and IVs
        for pad_label, pt_in in [
            ("nonce_zero48", NONCE + bytes(48 - len(NONCE))),
            ("nonce_pkcs7_48", pad(NONCE, 16)),
            ("nonce_rand32_zero16", NONCE[4:] + bytes(16)),
            ("nonce_rand32_pkcs7", pad(NONCE[4:], 16)),
        ]:
            if len(pt_in) % 16 != 0:
                continue
            for iv_label, iv_enc in [
                ("iv=zeros16", bytes(16)),
                ("iv=nonce[0:16]", NONCE[:16]),
                ("iv=nonce[4:20]", NONCE[4:20]),
                ("iv=nonce[20:36]", NONCE[20:36]),
            ]:
                cipher = AES.new(key, AES.MODE_CBC, iv_enc)
                ct_enc = cipher.encrypt(pt_in)
                # response would be IV || CT if IV is chosen; or just CT if IV=zeros
                label = f"AES-256-CBC-enc({key_label}, {iv_label}, {pad_label})"
                check(label, ct_enc)
                # also check IV prepended
                check(label + " [IV||CT]", iv_enc + ct_enc)

    # AES-256-ECB (no IV)
    for key_label, key in [("key_le", KEY_LE), ("key_be", KEY_BE)]:
        try:
            from Crypto.Cipher import AES as _AES
        except ImportError:
            break
        for pad_label, pt_in in [
            ("nonce_zero64", NONCE + bytes(64 - len(NONCE))),
            ("nonce_zero48", NONCE + bytes(48 - len(NONCE))),
        ]:
            if len(pt_in) % 16 != 0:
                continue
            cipher = _AES.new(key, _AES.MODE_ECB)
            ct_enc = cipher.encrypt(pt_in)
            check(f"AES-256-ECB-enc({key_label}, {pad_label})", ct_enc)


def run_chacha_tests() -> None:
    print("\n-- ChaCha20 / Salsa20 tests -------------------------------------")
    try:
        from Crypto.Cipher import ChaCha20, Salsa20
    except ImportError:
        print("  pycryptodome not installed — skipping")
        return

    for key_label, key in [("key_le", KEY_LE), ("key_be", KEY_BE)]:
        for nonce_label, nonce_val in [
            ("nonce8=zeros", bytes(8)),
            ("nonce8=nonce[0:8]", NONCE[:8]),
            ("nonce8=nonce[4:12]", NONCE[4:12]),
            ("nonce12=zeros", bytes(12)),
            ("nonce12=nonce[0:12]", NONCE[:12]),
            ("nonce12=nonce[4:16]", NONCE[4:16]),
        ]:
            nonce_bytes = nonce_val
            try:
                if len(nonce_bytes) in (8, 12):
                    cipher = ChaCha20.new(key=key, nonce=nonce_bytes)
                    ct = cipher.encrypt(NONCE + bytes(64 - len(NONCE)))
                    check(f"ChaCha20({key_label}, {nonce_label}, nonce_zero64)", ct[:64])
            except (ValueError, TypeError):
                pass

            try:
                if len(nonce_bytes) == 8:
                    cipher = Salsa20.new(key=key, nonce=nonce_bytes)
                    ct = cipher.encrypt(NONCE + bytes(64 - len(NONCE)))
                    check(f"Salsa20({key_label}, {nonce_label}, nonce_zero64)", ct[:64])
            except (ValueError, TypeError):
                pass


def main() -> None:
    print("CTCDC.dll key (LE, as extracted):", KEY_LE.hex())
    print("CTCDC.dll key (BE, word-swapped): ", KEY_BE.hex())
    print("Challenge nonce:", NONCE.hex(), f"({len(NONCE)} bytes)")
    print("Expected response:", RESPONSE.hex(), f"({len(RESPONSE)} bytes)")

    run_hmac_tests()
    run_aes_tests()
    run_chacha_tests()

    print()
    print("=" * 60)
    if FOUND:
        print(f"MATCHING ALGORITHM(S) FOUND:")
        for f in FOUND:
            print(f"  {f}")
    else:
        print("No direct match found.")
        print("The algorithm may use a custom mixing step or random IV embedded")
        print("in the response. Next: inspect FUN_1000ff10 and FUN_1000d300 in Ghidra.")


if __name__ == "__main__":
    main()