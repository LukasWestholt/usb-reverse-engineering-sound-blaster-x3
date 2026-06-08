#!/usr/bin/env python3
"""Enumerate Sound Blaster X3 interfaces and endpoints."""
import usb.core
import usb.util

VENDOR_ID = 0x041E
PRODUCT_ID = 0x3264

dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
if dev is None:
    raise SystemExit("Device not found. Is it connected?")

def safe(attr):
    try:
        return getattr(dev, attr)
    except Exception:
        return "(permission denied — run as root or add udev rule)"

print(f"Found: {safe('manufacturer')} {safe('product')}")
print(f"Bus {dev.bus:03d} Device {dev.address:03d}")
print(f"Serial: {safe('serial_number')}")
print()

cfg = dev.get_active_configuration()
for intf in cfg:
    cls = intf.bInterfaceClass
    sub = intf.bInterfaceSubClass
    proto = intf.bInterfaceProtocol
    label = {3: "HID", 1: "Audio"}.get(cls, f"Class 0x{cls:02x}")
    print(f"Interface {intf.bInterfaceNumber} alt={intf.bAlternateSetting}  [{label} sub={sub} proto={proto}]")
    for ep in intf:
        direction = "IN " if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN else "OUT"
        xfer = {0: "Control", 1: "Isochronous", 2: "Bulk", 3: "Interrupt"}[ep.bmAttributes & 0x03]
        print(f"  EP 0x{ep.bEndpointAddress:02x} {direction} {xfer:15s} maxPacket={ep.wMaxPacketSize}")