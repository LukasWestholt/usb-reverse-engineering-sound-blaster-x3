# Sound Blaster X3 USB Reverse Engineering

## Goal
Replicate the headset ↔ speaker output switch that normally requires the Windows driver or a physical button press, so it can be triggered programmatically on Linux.

**Status: FULLY IMPLEMENTED. Handshake key and algorithm extracted; `send_tty.py` can initialise the device from cold.**

The `5a 2c 05 00 [mode] 00 00 00` SET command is confirmed correct. Newer firmware requires a startup handshake (AES-256-GCM challenge-response) before accepting any 5A commands. The key has been extracted from `CTCDC.dll` and the algorithm reverse-engineered. Use `--handshake` to initialise a cold device.

```bash
# Linux — switch output (device must already be initialised, or use --handshake)
sudo .venv/bin/python scripts/send_tty.py headset --handshake   # cold device
sudo .venv/bin/python scripts/send_tty.py headset               # already initialised
```

## Device
- **USB ID**: `041e:3264` (lsusb shows "Sound Blaster X3")
- **Bus**: 001, Device 070 (address may change after replug)
- **Serial**: 49301A713EE*****

## Interface layout
| Interface | Class | Driver (Linux) | Purpose |
|-----------|-------|----------------|---------|
| 0 | HID | none | Button events (EP 0x86 IN interrupt) |
| 1 | CDC ACM | cdc_acm | Command channel — control/status |
| 2 | CDC Data | cdc_acm | Command channel — bulk data (EP 0x03 OUT, EP 0x82 IN) |
| 3 | Audio Control | snd-usb-audio | Mixer/DSP control (EP 0x84 IN interrupt) |
| 4 | Audio Streaming | snd-usb-audio | Playback (EP 0x01 OUT isochronous, many alt settings) |
| 5 | Audio Streaming | snd-usb-audio | Capture/mic (EP 0x81 IN isochronous) |
| 6 | Audio Streaming | snd-usb-audio | Second output stream |

**Key insight**: Interfaces 1+2 (cdc_acm) expose `/dev/ttyACM0` on Linux — this is the proprietary command channel.

ALSA/alsamixer has no visibility into the output switch; it is vendor-specific and goes over this CDC bulk pipe.

## Startup handshake (newer firmware, required before any 5A command)

The CDC channel (`/dev/ttyACM0` / `COM3`) requires a text-phase handshake before the device will respond to 5A binary commands. Older firmware (e.g. SoundBlasterX G6) skips this entirely; CTCDC.dll contains the branch: *"No unlocking is necessary because of old firmware."*

### Handshake sequence

```
Host  -> "whoareyou.MyApp8\r\n"
         (retry every ~2 s until device responds — device needs boot time)

Device-> "whoareyou" + <36-byte nonce> + "\r\n"
         (or "NotYet\r\n" if still booting)
         nonce structure: 4 fixed bytes (1e 04 64 32) + 32 random bytes

Host  -> "unlock" + <64-byte AES-256-GCM payload> + "\r\n"
         payload = iv(16) + ct(32) + gcm_tag(16)

Device-> "unlock_OK\r\n"   (success) or "unlock_FAIL\r\n" (wrong key/response)

Host  -> "SW_MODE1\r\n"    (enter software-control mode)

Device-> 5B 02 0A 00 <10 bytes firmware info>
         (e.g. 6d 00 00 00 00 00 00 00 00 00; first byte may be firmware build)
```

After this, the 5A binary protocol works. The device sends `5a 03 02 3b 00` in response to a `5a 03 00` ping.

### AES-256-GCM algorithm (fully extracted from CTCDC.dll)

```python
def compute_unlock_response(nonce: bytes) -> bytes:
    key = _load_key()                                    # 32 bytes from SB_CTCDC_KEY env var
    # nonce[0:4] is always 1e 04 64 32 (fixed header); the mixing is therefore constant
    session_key = nonce[0:2] + key[2:30] + nonce[2:4]   # 32-byte AES-256-GCM key
    iv  = os.urandom(16)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=iv[:12])
    ct, tag = cipher.encrypt_and_digest(nonce[4:])      # encrypt the 32 random challenge bytes
    return iv + ct + tag                                 # 16 + 32 + 16 = 64 bytes
```

Implemented in `scripts/send_tty.py` (`compute_unlock_response`) and callable via `--handshake`.
The key is loaded from the `SB_CTCDC_KEY` environment variable — not hardcoded in source.

| Item | Value |
|------|-------|
| Algorithm | AES-256-GCM |
| Key location | `CTCDC.dll` addresses `0x101d9a74`–`0x101d9a93` (32 raw bytes) |
| Key function | `FUN_1000d330` / `DoExecuteCommand_CTCDCCMD_Unlock` in Ghidra |
| Session key | `nonce[0:2] + KEY[2:30] + nonce[2:4]` — constant since nonce header is fixed |
| GCM nonce | First 12 bytes of the random IV |
| Plaintext | `nonce[4:]` — the 32 random challenge bytes |
| Response format | `iv(16) \|\| ct(32) \|\| gcm_tag(16)` = 64 bytes |
| Verified against | Wireshark capture `capture-app-startup-2.pcapng` — CT and tag match exactly |

**To use:** extract 32 bytes from `0x101d9a74`–`0x101d9a93` in your own copy of
`C:\Program Files (x86)\Creative\Creative App\CTCDC.dll` using Ghidra, then:
```bash
export SB_CTCDC_KEY=<64 hex chars>
sudo .venv/bin/python scripts/send_tty.py headset --handshake
```

## Discovered protocol (device → host notifications)

Packet format: `5a [cmd] [len] [payload * len]`

`5a` is always the start byte. Sub-items inside large payloads use `96 [id] [4-byte value]`.

### Known packets (device → host, sent when state changes)

| cmd | payload | meaning |
|-----|---------|---------|
| `0x2c` | `01 04 00 00 00` | Output mode = **headset** |
| `0x2c` | `01 01 00 00 00` | Output mode = **speaker** |
| `0x24` | `00 00` | (unknown — always `00 00`, sent during mode change) |
| `0x1a` | `02 00` | (unknown — always `02 00`, sent during mode change) |
| `0x11` | `09 01` + nine `96 [id] 00 00 00 00` items | DSP/EQ parameter block |
| `0x26` | `08 ff ff 00 00 00 00 00 00 00 00` | (unknown — constant) |
| `0x23` | `00` + `e6 ee` × 7 + `b1 dd` | Audio terminal routing — **speaker** mode |
| `0x23` | `01` + `4c f4` × 8 | Audio terminal routing — **headset** mode |

The full state dump is sent every time the button is pressed. The `0x2c` packet is the key — byte index 1 of the payload is the mode selector. The first byte of `0x23` also reliably distinguishes modes: `00` = speaker, `01` = headset.

### Output modes
- `0x04` = headset output
- `0x01` = speaker output (or no headset)
- Other values likely exist for optical/line output

## Discovered protocol (host → device SET commands)

Same `5a [cmd] [len] [payload]` framing, but byte[3] is `0x00` for host commands vs `0x01` in device notifications.

| command | payload | meaning |
|---------|---------|---------|
| `5a 2c 05 00 01 00 00 00` | — | **Set output = speaker** |
| `5a 2c 05 00 04 00 00 00` | — | **Set output = headset** |
| `5a 1a 03 01 02 00` | — | Follows mode switch (purpose unclear) |
| `5a 17 04 01 02 00 00` | — | Query EQ parameters (page 0) |
| `5a 17 04 01 02 00 02` | — | Query EQ parameters (page 2) |
| `5a 11 03 01 96 0a` | — | Poll DSP param 0x0a (repeated ~14× at 60 ms) |

**Device ACK sequence** (device → host, follows immediately after SET):
1. `5a 02 0a 2c 00 ...` — generic ACK (cmd=0x02, byte[3] echoes the SET cmd byte `0x2c`)
2. `5a 2c 05 01 [mode] 00 00 00` — state-change notification confirming new mode

The minimal command to switch output is just the single `5a 2c 05 00 [mode] 00 00 00` packet. The Creative app sends follow-up EQ queries after that, but they appear to be informational only.

## Scripts
Linux scripts require root (`sudo`). Windows scripts run as a normal user.

| Script | Platform | Purpose |
|--------|----------|---------|
| `find_device.py` | Linux | Enumerate interfaces and endpoints |
| `listen_tty.py` | Linux/Windows | Read raw bytes from the CDC command channel |
| `send_tty.py` | Linux/Windows | Write a command to the CDC channel; `--handshake` for cold device |
| `capture_usbmon.py` | Linux | Passive usbmon capture (needs `sudo modprobe usbmon`) |
| `replay.py` | Linux | Low-level pyusb control/bulk/HID probing |
| `find_com_port.py` | Windows | Auto-detect the Sound Blaster COM port |
| `parse_pcap.py` | Windows | Extract bulk OUT packets from a Wireshark pcapng (needs tshark) |
| `test_handshake.py` | Windows/Linux | Run the real AES-256-GCM handshake against a cold device |
| `test_crypto.py` | Any | Verify the extracted key against the known challenge-response pair |

### Linux commands
```bash
# Watch device notifications (press button while running)
sudo .venv/bin/python scripts/listen_tty.py --out capture.bin

# Try sending a SET command (format TBD from Windows capture)
sudo .venv/bin/python scripts/send_tty.py headset
sudo .venv/bin/python scripts/send_tty.py speaker

# Passive USB capture (both directions via kernel)
sudo modprobe usbmon
sudo .venv/bin/python scripts/capture_usbmon.py --bus 1 --dev 70 --out capture.txt
```

### Windows commands
```powershell
# 1. Find which COM port the device is on
uv run python scripts/find_com_port.py

# 2. Listen on that COM port — press button to see device notifications
uv run python scripts/listen_tty.py --dev COM3

# 3. Test the full handshake against a cold device (stop Creative app first)
uv run python scripts/test_handshake.py --dev COM3

# 4. Send a command (device already initialised by Creative app)
uv run python scripts/send_tty.py headset --dev COM3

# 5. Send a command on a cold device (handshake included)
uv run python scripts/send_tty.py headset --dev COM3 --handshake
```

## Windows capture plan (find the SET command)
1. Install **Wireshark** with the **USBPcap** component (default install includes it)
2. Run `find_com_port.py` — note the COM port (e.g. `COM3`)
3. Run `listen_tty.py --dev COM3` — press the button; should show `5a 2c ...` notifications
4. Open Wireshark → **Capture > Options** → select the **USBPcap** interface that lists the Sound Blaster
5. Start capture, then use the **Creative app** to switch headset ↔ speaker
6. Stop capture, save as `capture.pcapng`
7. Run `parse_pcap.py capture.pcapng` — bulk OUT packets to EP 0x03 are the SET commands
8. Identify the payload from the Creative app's switch action — that is the `host → device` protocol

### Wireshark display filter (during capture)
```
usb.idVendor == 0x041e
```

### Wireshark display filter (post-capture, to isolate SET command)
```
usb.transfer_type == 3 && usb.endpoint_address == 0x03
```

## Stack
- Python 3.14, Django 6 (future web UI), pyusb 1.3.1, pyserial 3.5
- Package manager: `uv`