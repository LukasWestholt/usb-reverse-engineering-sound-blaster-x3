#!/usr/bin/env python3
"""
Find the Windows COM port for the Sound Blaster X3 CDC ACM interface.

The Creative driver exposes the device's command channel as a virtual COM port.
Use the returned port name with listen_tty.py / send_tty.py via --dev.

Usage:
    python scripts/find_com_port.py
"""
import sys

import serial.tools.list_ports

VENDOR_ID = 0x041E
PRODUCT_ID = 0x3264


def main() -> None:
    matches = [
        p for p in serial.tools.list_ports.comports()
        if p.vid == VENDOR_ID and p.pid == PRODUCT_ID
    ]
    if not matches:
        print(
            "Sound Blaster X3 COM port not found.\n"
            "Checklist:\n"
            "  1. Device is plugged in\n"
            "  2. Creative app / driver is installed (it registers the COM port)\n"
            "  3. Device Manager > Ports (COM & LPT) — look for 'Sound Blaster' or 'USB Serial'\n"
            "  4. Try running with --all to list every serial port",
            file=sys.stderr,
        )
        sys.exit(1)

    for p in matches:
        print(f"{p.device}  —  {p.description}  (VID={p.vid:04X} PID={p.pid:04X})")
        print(f"  Run: python scripts/listen_tty.py --dev {p.device}")
        print(f"  Run: python scripts/send_tty.py headset --dev {p.device}")


if __name__ == "__main__":
    main()