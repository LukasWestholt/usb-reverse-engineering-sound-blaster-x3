#!/usr/bin/env python3
"""
Listen on /dev/ttyACM0 (Sound Blaster CDC command channel).
Press the headset/speaker button and watch what the device sends.

Usage:
    sudo python scripts/listen_tty.py [--dev /dev/ttyACM0] [--out capture.bin]
"""
import argparse
import sys
import time
import serial


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dev", default="/dev/ttyACM0")
    p.add_argument("--out", help="Save raw bytes to this file")
    p.add_argument("--timeout", type=float, default=0.1, help="Read timeout seconds (default 0.1)")
    return p.parse_args()


def main():
    args = parse_args()
    out = open(args.out, "wb") if args.out else None

    print(f"Opening {args.dev} in raw mode...")
    port = serial.Serial(
        args.dev,
        baudrate=9600,   # baud doesn't matter for CDC ACM / USB
        timeout=args.timeout,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        xonxoff=False,
        rtscts=False,
        dsrdtr=False,
    )
    print(f"Listening. Press headset/speaker button now. Ctrl+C to stop.\n")

    try:
        while True:
            data = port.read(512)
            if data:
                ts = time.strftime("%H:%M:%S")
                print(f"[{ts}] recv {len(data):3d} bytes: {data.hex()}  {list(data)}")
                if out:
                    out.write(data)
                    out.flush()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        port.close()
        if out:
            out.close()
            print(f"Saved to {args.out}")


if __name__ == "__main__":
    main()