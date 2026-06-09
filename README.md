# Sound Blaster X3 — Programmatic Output Switching

Switch the headset/speaker output on a Creative Sound Blaster X3 (USB ID `041e:3264`) without the Windows driver or physical button press. The X4 may also work (same USB ID, same protocol).

## Quick start (Linux)

```bash
uv sync

# Device already initialised (Creative app ran once, or firmware is old):
sudo SB_CTCDC_KEY=<hex> .venv/bin/python scripts/send_tty.py headset

# Cold device — perform the AES-256-GCM startup handshake first:
sudo SB_CTCDC_KEY=<hex> .venv/bin/python scripts/send_tty.py headset --handshake
```

See [Setup: extracting the key](#setup-extracting-the-key) for how to get `SB_CTCDC_KEY`.

The device exposes a CDC ACM serial port (`/dev/ttyACM0`) that accepts vendor commands directly. No kernel module, no libusb, no root beyond opening the serial port (fixable with a udev rule).

## Setup: extracting the key

Newer firmware (≥ 1.9.x) requires an AES-256-GCM challenge-response handshake before the device accepts any commands. The algorithm is open-source; the 32-byte secret key is embedded in Creative's proprietary `CTCDC.dll` — you must extract it from **your own legal copy**.

**Step 1 — Locate the file (Windows)**

```
C:\Program Files (x86)\Creative\Creative App\CTCDC.dll
```

**Step 2 — Open in Ghidra**

1. Download [Ghidra](https://ghidra-sre.org/) and create a new project
2. Import `CTCDC.dll` (File → Import File)
3. Let it auto-analyse (accept defaults, wait ~1 min)

**Step 3 — Navigate to the key**

Press **`G`** (Go To Address) and enter `101d9a74`.

Read the **32 consecutive raw bytes** at `0x101d9a74`–`0x101d9a93`.
They appear immediately after the `"Unknown command\r\n"` string and before
the first pointer at `0x101d9a94`. Copy them as a 64-character hex string.

**Step 4 — Verify your extraction**

```bash
python3 -c "
import hashlib
key = bytes.fromhex('<your 64 hex chars>')
print(hashlib.sha256(key).hexdigest())
"
```

The output must match this SHA-256 fingerprint (one-way hash — cannot be reversed to recover the key):

```
d9209f4b037d4d4323df8999c681124e3c91a02a201a1ea417a31ef764fd5ef2
```

**Step 5 — Export**

```bash
export SB_CTCDC_KEY=<your 64 hex chars>
# or persist it:
mkdir -p ~/.config/soundblaster
echo '<hex>' > ~/.config/soundblaster/ctcdc.key
```

## How it works

The Sound Blaster exposes seven USB interfaces. Interfaces 1+2 form a CDC ACM pair that the Creative driver uses as a proprietary command channel. On Linux this appears as `/dev/ttyACM0`; on Windows as a COM port (e.g. `COM3`).

### Startup handshake (firmware ≥ 1.9.x)

Before the device accepts any binary commands, it requires an AES-256-GCM challenge-response:

```
Host   → "whoareyou.MyApp8\r\n"           (poll every ~2 s until ready)
Device ← "whoareyou" + nonce(36) + "\r\n" (4 fixed bytes + 32 random bytes)
Host   → "unlock" + response(64) + "\r\n" (iv(16) + AES-256-GCM-ct(32) + tag(16))
Device ← "unlock_OK\r\n"
Host   → "SW_MODE1\r\n"
Device ← 5B frame (firmware info)
         [5A binary protocol now active]
```

The algorithm was reverse-engineered from `CTCDC.dll` using Ghidra. The implementation is in `scripts/send_tty.py`; the key must be supplied by the user (see Setup above).

### Binary command framing

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
| `send_tty.py` | Linux/Windows | Send a SET command; `--handshake` for cold device |
| `listen_tty.py` | Linux/Windows | Watch raw device notifications (press button to trigger) |
| `test_handshake.py` | Linux/Windows | Run and verify the full AES-256-GCM handshake |
| `test_crypto.py` | Any | Verify your extracted key against a known challenge-response |
| `find_com_port.py` | Windows | Auto-detect the Sound Blaster COM port |
| `parse_pcap.py` | Windows | Decode a Wireshark USBPcap capture |
| `capture_usbmon.py` | Linux | Passive capture via kernel usbmon |
| `find_device.py` | Linux | Enumerate USB interfaces and endpoints |
| `replay.py` | Linux | Low-level pyusb probing |

### Linux

```bash
export SB_CTCDC_KEY=<hex>   # see Setup section above

# Switch output (cold device — handshake included)
sudo SB_CTCDC_KEY=$SB_CTCDC_KEY .venv/bin/python scripts/send_tty.py headset --handshake
sudo SB_CTCDC_KEY=$SB_CTCDC_KEY .venv/bin/python scripts/send_tty.py speaker --handshake

# Device already initialised (no handshake needed)
sudo SB_CTCDC_KEY=$SB_CTCDC_KEY .venv/bin/python scripts/send_tty.py headset

# Send arbitrary hex payload
sudo SB_CTCDC_KEY=$SB_CTCDC_KEY .venv/bin/python scripts/send_tty.py raw 5a2c050004000000

# Test the handshake against a cold device
sudo SB_CTCDC_KEY=$SB_CTCDC_KEY .venv/bin/python scripts/test_handshake.py

# Watch device notifications (press button while running)
sudo .venv/bin/python scripts/listen_tty.py

# Passive USB capture (both directions)
sudo modprobe usbmon
sudo .venv/bin/python scripts/capture_usbmon.py --bus 1 --dev 70
```

### Windows

```powershell
$env:SB_CTCDC_KEY = "<hex>"   # see Setup section above

# Find the COM port
uv run python scripts/find_com_port.py

# Switch output (cold device — handshake included)
uv run python scripts/send_tty.py headset --dev COM3 --handshake

# Test the handshake
uv run python scripts/test_handshake.py --dev COM3

# Watch device notifications
uv run python scripts/listen_tty.py --dev COM3

# Parse a Wireshark capture
uv run python scripts/parse_pcap.py capture.pcapng --both-dirs --out findings.txt
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