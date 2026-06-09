#!/usr/bin/env python3
"""
Test the Sound Blaster X3/X4 startup handshake using the extracted AES-256-GCM key.

Algorithm (reverse-engineered from CTCDC.dll, confirmed against Wireshark capture):
  key     = nonce[0:2] + KEY_STATIC[2:30] + nonce[2:4]   (32 bytes; constant since nonce[0:4]=1e046432)
  iv      = os.urandom(16)
  payload = iv + AES-256-GCM(key, iv[:12]).encrypt_and_digest(nonce[4:])   -> 64 bytes
  frame   = b"unlock" + payload + b"\\r\\n"

Run WITHOUT the Creative app running so the device starts cold.

Usage:
    uv run python scripts/test_handshake.py
    uv run python scripts/test_handshake.py --dev COM3
"""
import argparse
import sys
import time
import serial

# Import the shared handshake implementation from send_tty
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from send_tty import compute_unlock_response, open_port, read_line


def attempt_real_handshake(port: serial.Serial) -> bool:
    """Full handshake using the extracted AES-256-GCM key."""
    print("\n=== Real handshake (AES-256-GCM) ===")

    nonce: bytes = b""
    for attempt in range(15):
        print(f"  [{attempt+1}] whoareyou.MyApp8 ->")
        port.reset_input_buffer()
        port.write(b"whoareyou.MyApp8\r\n")
        port.flush()
        resp = read_line(port, timeout=2.5)
        print(f"       <- {resp!r}")
        if resp.startswith(b"whoareyou") and resp.endswith(b"\r\n"):
            nonce = resp[9:-2]
            print(f"  nonce ({len(nonce)} bytes): {nonce.hex()}")
            break
        if resp == b"NotYet\r\n":
            print("  NotYet — retrying...")
            time.sleep(2.0)

    if not nonce:
        print("  ERROR: device never challenged us.")
        return False

    payload = compute_unlock_response(nonce)
    print(f"  unlock ({len(payload)}-byte AES-256-GCM payload) ->")
    port.write(b"unlock" + payload + b"\r\n")
    port.flush()

    ack = read_line(port, timeout=3.0)
    print(f"  <- {ack!r}")

    if ack == b"unlock_OK\r\n":
        print("  *** unlock_OK — handshake SUCCEEDED! ***")
        return True
    else:
        print(f"  FAILED: got {ack!r}")
        return False


def do_sw_mode(port: serial.Serial) -> None:
    print("\n  SW_MODE1 ->")
    port.write(b"SW_MODE1\r\n")
    port.flush()
    resp = port.read(32)
    print(f"  <- {resp.hex()}")


def do_5a_ping(port: serial.Serial) -> None:
    print("\n  5A ping (5a 03 00) ->")
    port.write(bytes.fromhex("5a0300"))
    port.flush()
    time.sleep(0.3)
    resp = port.read(64)
    if resp:
        print(f"  <- {resp.hex()}")
    else:
        print("  (no response)")


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--dev", default="COM3", help="COM port (default: COM3)")
    args = p.parse_args()

    port = open_port(args.dev)
    print(f"Opened {args.dev}")

    ok = attempt_real_handshake(port)
    if ok:
        do_sw_mode(port)
        do_5a_ping(port)

    port.close()

    print("\n=== Result ===")
    if ok:
        print("  Handshake: ACCEPTED")
        print("  The AES-256-GCM key is correct and the implementation works.")
    else:
        print("  Handshake: FAILED")


if __name__ == "__main__":
    main()