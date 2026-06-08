# Sound Blaster X3 — Programmatic Output Switching

Switch the headset/speaker output on a Creative Sound Blaster X3 (USB ID `041e:3264`) without the Windows driver or physical button press. The X4 may also work (same USB ID, same protocol).

## Quick start (Linux)

```bash
uv sync
sudo .venv/bin/python scripts/send_tty.py headset
sudo .venv/bin/python scripts/send_tty.py speaker
```

The device exposes a CDC ACM serial port (`/dev/ttyACM0`) that accepts vendor commands directly. No kernel module, no libusb, no root beyond opening the serial port (fixable with a udev rule).

## How it works

The Sound Blaster exposes seven USB interfaces. Interfaces 1+2 form a CDC ACM pair that the Creative driver uses as a proprietary command channel. On Linux this appears as `/dev/ttyACM0`; on Windows as a COM port (e.g. `COM3`).

All packets use the framing `5a [cmd] [len] [payload×len]`. The output-mode command is `cmd=0x2c`:

| Direction | Packet | Meaning |
|-----------|--------|---------|
| host → device | `5a 2c 05 00 04 00 00 00` | Set output = **headset** |
| host → device | `5a 2c 05 00 01 00 00 00` | Set output = **speaker** |
| device → host | `5a 2c 05 01 04 00 00 00` | Notification: output is headset |
| device → host | `5a 2c 05 01 01 00 00 00` | Notification: output is speaker |

Byte[3] distinguishes host commands (`0x00`) from device notifications (`0x01`). The device ACKs immediately with `5a 02 0a 2c ...` and then sends the matching notification.

## Scripts

| Script | Platform | Purpose |
|--------|----------|---------|
| `send_tty.py` | Linux / Windows | Send a SET command and print the response |
| `listen_tty.py` | Linux / Windows | Watch raw device notifications (press button to trigger) |
| `find_com_port.py` | Windows | Auto-detect the Sound Blaster COM port |
| `parse_pcap.py` | Windows | Extract bulk OUT packets from a Wireshark pcapng |
| `capture_usbmon.py` | Linux | Passive capture via kernel usbmon |
| `find_device.py` | Linux | Enumerate USB interfaces and endpoints |
| `replay.py` | Linux | Low-level pyusb probing |

### Linux

```bash
# Switch output
sudo .venv/bin/python scripts/send_tty.py headset
sudo .venv/bin/python scripts/send_tty.py speaker

# Send arbitrary hex payload
sudo .venv/bin/python scripts/send_tty.py raw 5a2c050004000000

# Watch device notifications (press button while running)
sudo .venv/bin/python scripts/listen_tty.py

# Passive USB capture (both directions)
sudo modprobe usbmon
sudo .venv/bin/python scripts/capture_usbmon.py --bus 1 --dev 70
```

### Windows

```powershell
# Find the COM port
uv run python scripts/find_com_port.py

# Switch output
uv run python scripts/send_tty.py headset --dev COM3
uv run python scripts/send_tty.py speaker --dev COM3

# Watch device notifications
uv run python scripts/listen_tty.py --dev COM3

# Parse a Wireshark capture for bulk OUT packets
uv run python scripts/parse_pcap.py capture.pcapng --out findings.txt
```

### Optional: udev rule (Linux, no sudo for serial port)

```bash
echo 'SUBSYSTEM=="tty", ATTRS{idVendor}=="041e", ATTRS{idProduct}=="3264", MODE="0666"' \
  | sudo tee /etc/udev/rules.d/99-soundblaster-x3.rules
sudo udevadm control --reload && sudo udevadm trigger
```

## Protocol reference

### Packet framing

```
5a [cmd:1] [len:1] [payload:len]
```

Sub-items inside large payloads use `96 [id:1] [value:4LE]`.

### Device → host notifications (sent on button press or state change)

| cmd | payload | meaning |
|-----|---------|---------|
| `0x2c` | `01 04 00 00 00` | Output mode = headset |
| `0x2c` | `01 01 00 00 00` | Output mode = speaker |
| `0x24` | `00 00` | Mode-change marker |
| `0x1a` | `02 00` | Mode-change marker |
| `0x11` | `09 01` + nine `96 [id] 00…` | DSP/EQ parameter block |
| `0x26` | `08 ff ff 00…` | Constant (purpose unknown) |
| `0x23` | `00` + `e6ee`×7 + `b1dd` | Audio terminal routing — speaker |
| `0x23` | `01` + `4cf4`×8 | Audio terminal routing — headset |

### Host → device SET commands

| packet | meaning |
|--------|---------|
| `5a 2c 05 00 01 00 00 00` | Set output = speaker |
| `5a 2c 05 00 04 00 00 00` | Set output = headset |
| `5a 17 04 01 02 00 00` | Query EQ parameters (page 0) |
| `5a 17 04 01 02 00 02` | Query EQ parameters (page 2) |
| `5a 11 03 01 96 0a` | Poll DSP param 0x0a |

Only the `5a 2c 05 00 [mode] 00 00 00` packet is needed to switch outputs. The Creative app sends EQ queries after that, but they are informational.

## How the SET command was found

1. Captured USB traffic on Windows using Wireshark + USBPcap while the Creative app switched outputs.
2. Filtered for `usb.transfer_type == 3 && usb.endpoint_address == 0x03` (bulk OUT to EP 3).
3. Extracted payloads via tshark field `usbcom.data.out_payload`.
4. Compared host commands against known device notifications — byte[3] is `0x00` in commands and `0x01` in notifications.

## Stack

- Python 3.14, pyserial 3.5, pyusb 1.3.1
- Package manager: `uv`
- Django 6 scaffolded for a future web UI