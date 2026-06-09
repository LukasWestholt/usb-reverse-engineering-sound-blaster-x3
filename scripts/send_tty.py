#!/usr/bin/env python3
"""
Send packets to Sound Blaster on /dev/ttyACM0 and print any response.

Protocol: 5a [cmd] [len] [payload * len]

Known cmd=0x2c output mode packet:
  headset:  5a 2c 05 00 04 00 00 00
  speaker:  5a 2c 05 00 01 00 00 00

Startup handshake (required on newer firmware before any 5A command):
  Host  -> "whoareyou.MyApp8\\r\\n"
  Device-> "whoareyou" + 36-byte nonce + "\\r\\n"
  Host  -> "unlock" + AES-256-GCM(key, iv[:12], nonce[4:]) + "\\r\\n"
  Device-> "unlock_OK\\r\\n"
  Host  -> "SW_MODE1\\r\\n"
  Device-> 5B frame (firmware info)

Usage:
    sudo python scripts/send_tty.py headset
    sudo python scripts/send_tty.py speaker
    sudo python scripts/send_tty.py raw 5a2c050004000000
    sudo python scripts/send_tty.py headset --dev /dev/ttyACM0 --handshake
"""
import argparse
import os
import sys
import time
import serial

try:
    from Crypto.Cipher import AES as _AES
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

PRESETS = {
    # Byte[3]=0x00 marks a host SET command; device notifications use 0x01 at that position.
    # Byte[4] is the mode: 0x04=headset, 0x01=speaker.
    "headset": bytes.fromhex("5a2c050004000000"),
    "speaker": bytes.fromhex("5a2c050001000000"),
}

def _load_key() -> bytes:
    """
    Load the 32-byte static key from the environment or a config file.

    Extract it from your own copy of CTCDC.dll using Ghidra:
      Address range: 0x101d9a74 – 0x101d9a93 (32 raw bytes)
      Function:      FUN_1000d330 / DoExecuteCommand_CTCDCCMD_Unlock

    Then set one of:
      export SB_CTCDC_KEY=<64 hex chars>          # environment variable
      echo <64 hex chars> > ~/.config/soundblaster/ctcdc.key  # config file
    """
    from pathlib import Path

    hex_key = os.environ.get("SB_CTCDC_KEY", "").strip()
    if not hex_key:
        cfg = Path.home() / ".config" / "soundblaster" / "ctcdc.key"
        if cfg.exists():
            hex_key = cfg.read_text().strip()

    if not hex_key:
        raise RuntimeError(
            "CTCDC key not set.\n"
            "Extract 32 bytes from 0x101d9a74–0x101d9a93 in CTCDC.dll (Ghidra)\n"
            "and set the SB_CTCDC_KEY environment variable (64 hex chars)."
        )
    try:
        key = bytes.fromhex(hex_key)
    except ValueError as e:
        raise RuntimeError(f"SB_CTCDC_KEY is not valid hex: {e}") from e
    if len(key) != 32:
        raise RuntimeError(f"SB_CTCDC_KEY must be 32 bytes (64 hex chars), got {len(key)}")
    return key


def _derive_key(nonce: bytes) -> bytes:
    """
    Mix nonce fixed-header into the static key to get the AES-256-GCM session key.
    
    The mixed key (used for AES-256-GCM) replaces bytes [0:2] with nonce[0:2]
    and bytes [30:32] with nonce[2:4].  Since nonce[0:4] is always 1e0464 32,
    the effective session key is always the same 32-byte value below.
    """
    key = _load_key()
    return nonce[0:2] + key[2:30] + nonce[2:4]


def compute_unlock_response(nonce: bytes) -> bytes:
    """
    Compute the 64-byte unlock payload for a given 36-byte device nonce.

    Algorithm (AES-256-GCM):
      key      = nonce[0:2] + KEY_STATIC[2:30] + nonce[2:4]   (32 bytes)
      iv       = os.urandom(16)
      gcm_iv   = iv[:12]
      ct, tag  = AES-256-GCM(key, gcm_iv).encrypt_and_digest(nonce[4:])
      payload  = iv(16) + ct(32) + tag(16)   → 64 bytes total
    """
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome required: uv add pycryptodome")
    key = _derive_key(nonce)
    iv = os.urandom(16)
    cipher = _AES.new(key, _AES.MODE_GCM, nonce=iv[:12])
    ct, tag = cipher.encrypt_and_digest(nonce[4:])
    return iv + ct + tag


def open_port(dev="/dev/ttyACM0"):
    return serial.Serial(
        dev, baudrate=9600, timeout=0.3,
        bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE, xonxoff=False, rtscts=False, dsrdtr=False,
    )


def read_line(port: serial.Serial, timeout: float = 5.0) -> bytes:
    """Read until CRLF or timeout."""
    deadline = time.monotonic() + timeout
    buf = b""
    while time.monotonic() < deadline:
        chunk = port.read(256)
        if chunk:
            buf += chunk
            if buf.endswith(b"\r\n"):
                return buf
    return buf


def do_handshake(port: serial.Serial, verbose: bool = True) -> bool:
    """
    Perform the startup text-phase handshake (required on firmware >= 1.9.x).
    Returns True if the device responded with unlock_OK and SW_MODE1 was sent.
    """
    if not _HAS_CRYPTO:
        print("ERROR: pycryptodome required for handshake.  Run: uv add pycryptodome", file=sys.stderr)
        return False

    for attempt in range(15):
        if verbose:
            print(f"  [{attempt+1}] whoareyou.MyApp8 ->")
        port.reset_input_buffer()
        port.write(b"whoareyou.MyApp8\r\n")
        port.flush()
        resp = read_line(port, timeout=2.5)
        if verbose:
            print(f"       <- {resp!r}")
        if resp.startswith(b"whoareyou") and resp.endswith(b"\r\n"):
            nonce = resp[9:-2]
            break
        if resp == b"NotYet\r\n":
            time.sleep(2.0)
    else:
        print("ERROR: device never sent a challenge — is it already initialised?")
        return False

    if verbose:
        print(f"  nonce ({len(nonce)} bytes): {nonce.hex()}")

    payload = compute_unlock_response(nonce)
    if verbose:
        print(f"  unlock -> (64-byte AES-256-GCM response)")
    port.write(b"unlock" + payload + b"\r\n")
    port.flush()

    ack = read_line(port, timeout=3.0)
    if verbose:
        print(f"  <- {ack!r}")
    if ack != b"unlock_OK\r\n":
        print(f"ERROR: expected unlock_OK, got {ack!r}")
        return False

    port.write(b"SW_MODE1\r\n")
    port.flush()
    sw_resp = port.read(32)
    if verbose:
        print(f"  SW_MODE1 <- {sw_resp.hex()}")
    return True


def send_and_recv(port, data: bytes, read_timeout=1.0) -> bytes:
    port.write(data)
    port.flush()
    print(f"  sent:  {data.hex()}")
    deadline = time.monotonic() + read_timeout
    buf = b""
    while time.monotonic() < deadline:
        chunk = port.read(512)
        if chunk:
            buf += chunk
    return buf


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mode", choices=list(PRESETS) + ["raw"], help="Preset name or 'raw'")
    p.add_argument("hex_data", nargs="?", help="Hex string when mode=raw, e.g. 5a2c050004000000")
    p.add_argument("--dev", default="/dev/ttyACM0")
    p.add_argument("--handshake", action="store_true",
                   help="Perform startup handshake before sending the command "
                        "(needed if device is cold / freshly plugged in)")
    return p.parse_args()


def main():
    args = parse_args()
    if args.mode == "raw":
        if not args.hex_data:
            print("raw mode requires a hex string argument", file=sys.stderr)
            sys.exit(1)
        data = bytes.fromhex(args.hex_data)
    else:
        data = PRESETS[args.mode]

    port = open_port(args.dev)
    print(f"Opened {args.dev}")

    if args.handshake:
        print("Performing startup handshake...")
        if not do_handshake(port):
            port.close()
            sys.exit(1)
        print("Handshake complete.")

    resp = send_and_recv(port, data)
    if resp:
        print(f"  response ({len(resp)} bytes): {resp.hex()}")
        i = 0
        while i < len(resp):
            if resp[i] == 0x5a and i + 2 < len(resp):
                cmd, length = resp[i+1], resp[i+2]
                payload = resp[i+3:i+3+length]
                print(f"    5a cmd={cmd:02x} len={length:02d} payload={payload.hex()}")
                i += 3 + length
            else:
                i += 1
    else:
        print("  no response")
    port.close()


if __name__ == "__main__":
    main()