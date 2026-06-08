#!/usr/bin/env python3
"""
Send packets to Sound Blaster on /dev/ttyACM0 and print any response.

Protocol: 5a [cmd] [len] [payload * len]

Known cmd=0x2c output mode packet:
  headset:  5a 2c 05 01 04 00 00 00
  speaker:  5a 2c 05 01 01 00 00 00

Usage:
    sudo python scripts/send_tty.py headset
    sudo python scripts/send_tty.py speaker
    sudo python scripts/send_tty.py raw 5a2c050104000000
"""
import argparse
import sys
import time
import serial

PRESETS = {
    # Byte[3]=0x00 marks a host SET command; device notifications use 0x01 at that position.
    # Byte[4] is the mode: 0x04=headset, 0x01=speaker.
    "headset": bytes.fromhex("5a2c050004000000"),
    "speaker": bytes.fromhex("5a2c050001000000"),
}


def open_port(dev="/dev/ttyACM0"):
    return serial.Serial(
        dev, baudrate=9600, timeout=0.3,
        bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE, xonxoff=False, rtscts=False, dsrdtr=False,
    )


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
    p.add_argument("hex_data", nargs="?", help="Hex string when mode=raw, e.g. 5a2c050104000000")
    p.add_argument("--dev", default="/dev/ttyACM0")
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
    resp = send_and_recv(port, data)
    if resp:
        print(f"  response ({len(resp)} bytes): {resp.hex()}")
        # Parse response packets
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
