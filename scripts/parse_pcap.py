#!/usr/bin/env python3
"""
Parse a Wireshark pcapng capture and extract USB bulk transfers for the Sound Blaster X3.

Requires tshark (installed with Wireshark).  Default: show only bulk OUT (host→device)
because those are the SET commands we need to discover.

Capture steps (Windows):
  1. Open Wireshark, select the USBPcap interface that contains the Sound Blaster
  2. Use the Creative app to switch headset ↔ speaker
  3. Stop capture, save as .pcapng
  4. Run: python scripts/parse_pcap.py capture.pcapng --dev <device-address>

Wireshark display filter to pre-filter during capture (optional):
  usb.idVendor == 0x041e

Usage:
    python scripts/parse_pcap.py capture.pcapng
    python scripts/parse_pcap.py capture.pcapng --dev 70
    python scripts/parse_pcap.py capture.pcapng --both-dirs
    python scripts/parse_pcap.py capture.pcapng --out findings.txt
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path


TSHARK_CANDIDATES = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

# Known device→host notification payloads (5A protocol)
KNOWN_NOTIFY: dict[tuple[int, bytes], str] = {
    (0x2C, bytes([0x01, 0x04, 0x00, 0x00, 0x00])): "NOTIFY  output_mode = HEADSET",
    (0x2C, bytes([0x01, 0x01, 0x00, 0x00, 0x00])): "NOTIFY  output_mode = SPEAKER",
    (0x24, bytes([0x00, 0x00])): "NOTIFY  (mode-change marker, cmd=24)",
    (0x1A, bytes([0x02, 0x00])): "NOTIFY  (mode-change marker, cmd=1a)",
}


def find_tshark() -> str:
    for candidate in TSHARK_CANDIDATES:
        if shutil.which(candidate) or Path(candidate).exists():
            return candidate
    print(
        "tshark not found.\n"
        "Install Wireshark and make sure tshark is in PATH, or install it at the default location.",
        file=sys.stderr,
    )
    sys.exit(1)


def decode_5a(data: bytes) -> str:
    """Return a human-readable description of a 5A-protocol packet."""
    if len(data) < 3 or data[0] != 0x5A:
        return f"(not 5A: {data[:8].hex()}{'…' if len(data) > 8 else ''})"
    cmd = data[1]
    length = data[2]
    payload = data[3: 3 + length]
    label = KNOWN_NOTIFY.get((cmd, bytes(payload)))
    if label:
        return label
    return f"5A cmd=0x{cmd:02X} len={length} payload={payload.hex()}"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("pcap", type=Path, help="pcap/pcapng file from Wireshark")
    p.add_argument("--dev", type=int, default=0, help="USB device address filter (0 = all)")
    p.add_argument(
        "--both-dirs",
        action="store_true",
        help="Show both IN (device→host) and OUT (host→device). Default: OUT only.",
    )
    p.add_argument("--out", type=Path, help="Write results to this file")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if not args.pcap.exists():
        print(f"File not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    tshark = find_tshark()

    display_filter = "usb.transfer_type == 3"  # bulk only
    if not args.both_dirs:
        display_filter += " && usb.endpoint_address.direction == 0"  # OUT = host→device
    if args.dev:
        display_filter += f" && usb.device_address == {args.dev}"

    proc = subprocess.run(
        [
            tshark, "-r", str(args.pcap),
            "-Y", display_filter,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "usb.device_address",
            "-e", "usb.endpoint_address",
            "-e", "usb.endpoint_address.direction",
            "-e", "usbcom.data.out_payload",
            "-E", "separator=\t",
            "-E", "header=y",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"tshark error:\n{proc.stderr}", file=sys.stderr)
        sys.exit(1)

    lines = proc.stdout.splitlines()
    if len(lines) <= 1:
        print("No matching bulk packets found.")
        if not args.dev:
            print("Tip: run without --dev first to see all device addresses, then retry with --dev <addr>")
        return

    out_file = open(args.out, "w") if args.out else None
    count = 0

    for line in lines[1:]:  # skip header row
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        frame_num = parts[0]
        time_rel = parts[1]
        dev_addr = parts[2]
        ep_hex = parts[3]
        direction = parts[4]
        capdata_raw = parts[5] if len(parts) > 5 else ""

        capdata_hex = capdata_raw.replace(":", "")
        try:
            ep = int(ep_hex, 16) if ep_hex else 0
        except ValueError:
            ep = 0
        try:
            t = float(time_rel)
        except ValueError:
            t = 0.0

        dir_label = "OUT (host->dev)" if direction == "0" else "IN  (dev->host)"

        annotation = ""
        if capdata_hex:
            try:
                raw = bytes.fromhex(capdata_hex)
                if raw and raw[0] == 0x5A:
                    annotation = f"\n      -> {decode_5a(raw)}"
                elif raw:
                    annotation = f"\n      -> (non-5A payload)"
            except ValueError:
                pass

        row = (
            f"#{frame_num:>5}  t={t:8.4f}s  dev={dev_addr:>3}  "
            f"EP=0x{ep:02X} {dir_label}  data={capdata_hex}{annotation}"
        )
        print(row)
        if out_file:
            out_file.write(row + "\n")
        count += 1

    dir_desc = "bulk" if args.both_dirs else "bulk OUT"
    summary = f"\n{count} {dir_desc} packet(s) found."
    print(summary)
    if out_file:
        out_file.write(summary + "\n")
        out_file.close()
        print(f"Saved to {args.out}")


if __name__ == "__main__":
    main()