#!/usr/bin/env python3
"""
Send vendor control transfers to Sound Blaster X3.

After capturing with capture_usbmon.py, paste the vendor command parameters here.

Must run as root, or set up udev rule:
    echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="041e", ATTR{idProduct}=="3264", MODE="0666"' \
        | sudo tee /etc/udev/rules.d/99-soundblaster-x3.rules
    sudo udevadm control --reload && sudo udevadm trigger
"""
import argparse
import sys
import usb.core
import usb.util

VENDOR_ID = 0x041E
PRODUCT_ID = 0x3264

# Known commands (fill in after capture analysis)
COMMANDS = {
    # "headset": {"bmRequestType": 0x40, "bRequest": 0x???, "wValue": 0x????, "wIndex": 0x????, "data": b""},
    # "speaker": {"bmRequestType": 0x40, "bRequest": 0x???, "wValue": 0x????, "wIndex": 0x????, "data": b""},
}


def open_device(detach_interfaces=(0,)):
    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if dev is None:
        raise SystemExit("Device not found.")
    for iface in detach_interfaces:
        try:
            if dev.is_kernel_driver_active(iface):
                dev.detach_kernel_driver(iface)
                print(f"  Detached kernel driver from interface {iface}")
        except usb.core.USBError as e:
            print(f"  Could not detach interface {iface}: {e}")
    return dev


def send_control(dev, bm_request_type: int, b_request: int, w_value: int, w_index: int, data: bytes = b"") -> bytes:
    if bm_request_type & 0x80:  # IN transfer
        result = dev.ctrl_transfer(bm_request_type, b_request, w_value, w_index, len(data) or 64)
        return bytes(result)
    else:  # OUT transfer
        n = dev.ctrl_transfer(bm_request_type, b_request, w_value, w_index, data)
        return bytes([n])


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    named = sub.add_parser("run", help="Run a named command from COMMANDS dict")
    named.add_argument("name", choices=list(COMMANDS) or ["(none defined yet)"])

    raw = sub.add_parser("raw", help="Send a raw control transfer")
    raw.add_argument("--bm", type=lambda x: int(x, 16), required=True, help="bmRequestType hex, e.g. 0x40")
    raw.add_argument("--req", type=lambda x: int(x, 16), required=True, help="bRequest hex")
    raw.add_argument("--val", type=lambda x: int(x, 16), default=0, help="wValue hex (default 0)")
    raw.add_argument("--idx", type=lambda x: int(x, 16), default=0, help="wIndex hex (default 0)")
    raw.add_argument("--data", type=bytes.fromhex, default=b"", help="Payload hex string, e.g. 010203")

    probe = sub.add_parser("probe-hid", help="Read HID interrupt endpoint (watch button events)")
    probe.add_argument("--timeout", type=int, default=10000, help="Read timeout ms (default 10000)")
    probe.add_argument("--count", type=int, default=10, help="Number of reads (default 10)")

    bulk = sub.add_parser("probe-bulk", help="Read CDC bulk IN endpoint EP 0x82 (watch device responses)")
    bulk.add_argument("--timeout", type=int, default=5000, help="Read timeout ms (default 5000)")
    bulk.add_argument("--count", type=int, default=20, help="Number of reads (default 20)")

    send_bulk = sub.add_parser("send-bulk", help="Send raw bytes to CDC bulk OUT endpoint EP 0x03")
    send_bulk.add_argument("data", type=bytes.fromhex, help="Hex string to send, e.g. 0102030405")

    return p.parse_args()


def main():
    args = parse_args()
    if args.cmd is None:
        print("Use --help to see available subcommands.")
        sys.exit(0)

    dev = open_device()
    print(f"Opened: {dev.manufacturer} {dev.product}  Bus {dev.bus:03d} Dev {dev.address:03d}")

    if args.cmd == "run":
        cmd = COMMANDS[args.name]
        result = send_control(dev, cmd["bmRequestType"], cmd["bRequest"], cmd["wValue"], cmd["wIndex"], cmd.get("data", b""))
        print(f"Result: {result.hex()}")

    elif args.cmd == "raw":
        result = send_control(dev, args.bm, args.req, args.val, args.idx, args.data)
        print(f"Result: {result.hex()}")

    elif args.cmd == "probe-hid":
        # HID interrupt endpoint EP 0x86 on interface 0
        usb.util.claim_interface(dev, 0)
        ep_addr = 0x86
        print(f"Reading EP 0x{ep_addr:02x} ({args.count}x, timeout {args.timeout}ms). Press device buttons now.")
        for i in range(args.count):
            try:
                data = dev.read(ep_addr, 64, timeout=args.timeout)
                print(f"  [{i+1:2d}] {bytes(data).hex()}  ({list(data)})")
            except usb.core.USBTimeoutError:
                print(f"  [{i+1:2d}] timeout")

    elif args.cmd == "probe-bulk":
        # CDC bulk IN endpoint EP 0x82 — device responses / unsolicited events
        ep_addr = 0x82
        if dev.is_kernel_driver_active(2):
            dev.detach_kernel_driver(2)
        print(f"Reading EP 0x{ep_addr:02x} ({args.count}x, timeout {args.timeout}ms). Press device buttons now.")
        for i in range(args.count):
            try:
                data = dev.read(ep_addr, 512, timeout=args.timeout)
                print(f"  [{i+1:2d}] {bytes(data).hex()}  len={len(data)}")
            except usb.core.USBTimeoutError:
                print(f"  [{i+1:2d}] timeout")

    elif args.cmd == "send-bulk":
        # CDC bulk OUT endpoint EP 0x03 — send vendor command
        if dev.is_kernel_driver_active(2):
            dev.detach_kernel_driver(2)
        n = dev.write(0x03, args.data)
        print(f"Sent {n} bytes")
        # Read response
        try:
            resp = dev.read(0x82, 512, timeout=2000)
            print(f"Response: {bytes(resp).hex()}  len={len(resp)}")
        except usb.core.USBTimeoutError:
            print("No response within 2s")

    usb.util.dispose_resources(dev)


if __name__ == "__main__":
    main()
