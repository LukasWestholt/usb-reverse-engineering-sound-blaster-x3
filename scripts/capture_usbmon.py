#!/usr/bin/env python3
"""
Read usbmon text stream and filter for Sound Blaster X3 control transfers.

Must run as root (or with access to /sys/kernel/debug/usb/usbmon/).
Prerequisites:
    sudo modprobe usbmon

Usage:
    sudo python scripts/capture_usbmon.py [--bus 1] [--dev 70] [--out capture.txt]
"""
import argparse
import sys
from pathlib import Path
from datetime import datetime


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bus", type=int, default=1, help="USB bus number (default: 1)")
    p.add_argument("--dev", type=int, default=0, help="USB device address to filter (0 = all)")
    p.add_argument("--out", type=Path, help="Save matching lines to this file")
    p.add_argument("--all", action="store_true", help="Show all transfers, not just control")
    return p.parse_args()


def parse_usbmon_line(line: str) -> dict | None:
    """
    usbmon text line format:
      URB_tag timestamp Event Pipe [s status] length [= data...]
    Event: S=Submit C=Complete e=Error
    Pipe:  Xc:bus:dev:ep  (X=C/I/B/Z, c=i/o)
    """
    parts = line.split()
    if len(parts) < 5:
        return None
    tag, ts, event, pipe = parts[0], parts[1], parts[2], parts[3]
    if ":" not in pipe:
        return None
    pipe_parts = pipe.split(":")
    if len(pipe_parts) != 4:
        return None
    xfer_dir, bus_s, dev_s, ep_s = pipe_parts
    try:
        bus = int(bus_s)
        dev = int(dev_s)
        ep = int(ep_s)
    except ValueError:
        return None

    xfer_type = xfer_dir[0].upper()  # C=Control, I=Interrupt, B=Bulk, Z=Isochronous
    direction = "IN" if xfer_dir[1].lower() == "i" else "OUT"

    result = {
        "tag": tag,
        "ts": ts,
        "event": event,  # S or C
        "xfer_type": xfer_type,
        "direction": direction,
        "bus": bus,
        "dev": dev,
        "ep": ep,
        "raw": line.rstrip(),
    }

    # For Submit lines with control setup packet: s bmRT bReq wVal wIdx wLen
    if event == "S" and xfer_type == "C" and len(parts) >= 10:
        try:
            result["bmRequestType"] = int(parts[4], 16)
            result["bRequest"] = int(parts[5], 16)
            result["wValue"] = int(parts[6], 16)
            result["wIndex"] = int(parts[7], 16)
            result["wLength"] = int(parts[8], 16)
        except (ValueError, IndexError):
            pass

    # Data bytes after "="
    if "=" in parts:
        eq_idx = parts.index("=")
        result["data"] = bytes.fromhex("".join(parts[eq_idx + 1:]))

    return result


def describe_control(urb: dict) -> str:
    rt = urb.get("bmRequestType", 0)
    req = urb.get("bRequest", 0)
    val = urb.get("wValue", 0)
    idx = urb.get("wIndex", 0)
    length = urb.get("wLength", 0)

    recipient = {0: "device", 1: "interface", 2: "endpoint", 3: "other"}.get(rt & 0x1F, "?")
    type_ = {0: "standard", 1: "class", 2: "vendor", 3: "reserved"}.get((rt >> 5) & 0x03, "?")
    direction = "IN" if rt & 0x80 else "OUT"

    desc = f"bmRT=0x{rt:02x}({type_}/{recipient}/{direction}) bReq=0x{req:02x} wVal=0x{val:04x} wIdx=0x{idx:04x} wLen={length}"
    return desc


def main():
    args = parse_args()
    mon_path = Path(f"/sys/kernel/debug/usb/usbmon/{args.bus}t")

    if not mon_path.exists():
        print(f"ERROR: {mon_path} not found.", file=sys.stderr)
        print("Run: sudo modprobe usbmon", file=sys.stderr)
        sys.exit(1)

    out_file = open(args.out, "w") if args.out else None
    print(f"Capturing on {mon_path}  (device filter: {'all' if not args.dev else args.dev})")
    print("Press the headset/speaker button now. Ctrl+C to stop.\n")

    try:
        with open(mon_path, "r") as f:
            for line in f:
                urb = parse_usbmon_line(line)
                if urb is None:
                    continue
                if args.dev and urb["dev"] != args.dev:
                    continue
                if not args.all and urb["xfer_type"] not in ("C", "I", "B"):
                    continue  # control + interrupt + bulk

                ts = datetime.now().strftime("%H:%M:%S.%f")
                prefix = f"[{ts}] {urb['event']} {urb['xfer_type']} dev={urb['dev']:3d} ep=0x{urb['ep']:02x}"

                if urb["xfer_type"] == "C" and urb["event"] == "S":
                    desc = describe_control(urb)
                    line_out = f"{prefix}  {desc}"
                    # Highlight vendor commands
                    rt = urb.get("bmRequestType", 0)
                    if (rt >> 5) & 0x03 == 2:
                        line_out = f"*** VENDOR *** {line_out}"
                elif "data" in urb and urb["data"]:
                    line_out = f"{prefix}  data={urb['data'].hex()}"
                else:
                    line_out = f"{prefix}  {urb['raw'][50:]}"

                print(line_out)
                if out_file:
                    out_file.write(urb["raw"] + "\n")
                    out_file.flush()

    except KeyboardInterrupt:
        print("\nCapture stopped.")
    finally:
        if out_file:
            out_file.close()
            print(f"Raw lines saved to {args.out}")


if __name__ == "__main__":
    main()