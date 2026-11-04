#!/usr/bin/env python3
"""
dxbeacon.py - configure DX-Smart CP27 (DA14531) beacons over BLE.

Protocol reverse-engineered from btsnoop captures of the DX-Smart app:

  Command  (write to cmd char):    4E 4F | CMD | LEN | DATA... | XOR(CMD,LEN,DATA)
  Write ack (notification):        4E 4F | CMD | 01  | 01      | XOR
  Read reply (notification):       raw data, usually starting with CMD echoed
  Auth: write ASCII password (default "dx1234") to the password char.

Requires:  pip install bleak
"""

import argparse
import asyncio
import os
import sys
import traceback

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

DEFAULT_PASSWORD = "dx1234"
STANDARD_SERVICES = {"1800", "1801", "180a", "180f"}
# "ShenZhenDaXi" OUI (seen on every DX-CP27 unit so far). Advertised name
# isn't reliable for filtering scan results: only the device-name frame
# (0x61) carries one, and most other frame types (iBeacon, Eddystone UID/
# URL/TLM, ACC) don't - so if the beacon happens to be mid-rotation to one
# of those when scanned, name-based matching misses it.
DX_OUI = "48:87:2D"

# Frame types (also the command byte used to read that frame's current content)
FRAME_DEVICE_NAME = 0x61
FRAME_IBEACON = 0x62
FRAME_UID = 0x63
FRAME_URL = 0x64
FRAME_TLM = 0x65
FRAME_ACC = 0x66
FRAME_USER = 0x67
FRAME_EMPTY = 0xFF

FRAME_NAMES = {
    FRAME_DEVICE_NAME: "Device name",
    FRAME_IBEACON: "iBeacon",
    FRAME_UID: "Eddystone-UID",
    FRAME_URL: "Eddystone-URL",
    FRAME_TLM: "Eddystone-TLM",
    FRAME_ACC: "ACC",
    FRAME_USER: "User",
    FRAME_EMPTY: "(empty)",
}
URL_SCHEMES = {0: "http://www.", 1: "https://www.", 2: "http://", 3: "https://"}
URL_EXPANSIONS = [".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
                  ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"]

# General commands
CMD_PREAUTH = 0x25          # pre-auth check, as the app does
SLOT_SELECT_BASE = 0x10     # bare: read slots list; +N (1-7): select slot N
CMD_DEVICE_INFO = 0x30
CMD_STATUS = 0x22
CMD_SAVE = 0xA0              # save (also clears any trigger)
CMD_SET_TRIGGER = 0xA2       # set trigger + save
CMD_READ_TRIGGER = 0xA1      # reply is junk; see _resolve_trigger
CMD_APPLY = 0x60
CMD_SET_PASSWORD = 0x24
CMD_FACTORY_RESET = 0x21
CMD_POWER_OFF = 0x23

# Per-field write opcodes, grouped by frame type
NAME_FIELD_NAME = 0x71       # variable length; firmware zero-pads to 28 bytes
NAME_FIELD_INTERVAL = 0x72
NAME_FIELD_TX_POWER = 0x73

IBEACON_FIELD_UUID = 0x74
IBEACON_FIELD_MAJOR = 0x75
IBEACON_FIELD_MINOR = 0x76
IBEACON_FIELD_MPOWER = 0x77
IBEACON_FIELD_INTERVAL = 0x78
IBEACON_FIELD_TX_POWER = 0x79

UID_FIELD_NAMESPACE = 0x81
UID_FIELD_INSTANCE = 0x82
UID_FIELD_MPOWER = 0x83
UID_FIELD_INTERVAL = 0x84
UID_FIELD_TX_POWER = 0x85

ACC_FIELD_INTERVAL = 0x93
ACC_FIELD_TX_POWER = 0x94

USER_FIELD_DATA = 0x95       # variable length; firmware zero-pads to 22 bytes
USER_FIELD_INTERVAL = 0x96
USER_FIELD_TX_POWER = 0x97

# Trigger: a one-shot action the beacon can take on a button double/triple
# click or on being picked up and moved. 0xa2 sets it (data: type, seconds -
# how long the beacon advertises after the trigger fires, 1-100), in place of
# the normal 0xA0 save, and must be followed by an 0xa1 call before 0x60
# apply or it doesn't commit - the app always does this, even though 0xa1's
# reply is junk. Read the actual state back via the iBeacon frame's own
# trailer instead (see _params below).
TRIGGER_NAMES = {0: "off", 1: "double-click", 2: "triple-click", 3: "move"}
TRIGGER_CODES = {v: k for k, v in TRIGGER_NAMES.items()}
DEFAULT_TRIGGER_SECONDS = 0x1E


class ProtocolError(Exception):
    pass


class AuthError(Exception):
    pass


def build_frame(cmd: int, data: bytes = b"") -> bytes:
    body = bytes([cmd, len(data)]) + data
    chk = 0
    for b in body:
        chk ^= b
    return b"NO" + body + bytes([chk])


# --------------------------------------------------------------------------
# Reply parsers
# --------------------------------------------------------------------------

def _params(trailer: bytes) -> dict:
    # Common trailer on every frame: interval, global TX power, then the
    # trigger state (enabled flag, mode, seconds) - not just "reserved".
    d = {"interval": trailer[0], "tx_power": trailer[1]}
    reserved = trailer[2:]
    if len(reserved) >= 3:
        d["trigger"] = TRIGGER_NAMES.get(reserved[1], f"0x{reserved[1]:02x}") if reserved[0] else "off"
        if reserved[0]:
            d["trigger_seconds"] = reserved[2]
    else:
        d["reserved"] = reserved.hex()
    return d


def decode_url(field: bytes) -> str:
    scheme = URL_SCHEMES.get(field[0], f"<scheme 0x{field[0]:02x}>")
    body = field[1:]
    stripped = body.rstrip(b"\x00")
    # 0x00 is also the ".com/" expansion, so padding is ambiguous.
    # Guess: if any zeros were stripped, the first one was ".com/".
    if len(stripped) < len(body):
        stripped += b"\x00"
    out = []
    for b in stripped:
        out.append(URL_EXPANSIONS[b] if b < len(URL_EXPANSIONS) else chr(b))
    return scheme + "".join(out)


def parse_frame(data: bytes) -> dict:
    t = data[0]
    d = {"type": FRAME_NAMES.get(t, f"0x{t:02x}"), "raw": data.hex()}
    if t == FRAME_DEVICE_NAME and len(data) >= 34:
        d["name"] = data[1:29].rstrip(b"\x00").decode(errors="replace")
        d.update(_params(data[29:]))
    elif t == FRAME_IBEACON and len(data) >= 27:
        u = data[1:17].hex()
        d["uuid"] = f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}".upper()
        d["major"] = int.from_bytes(data[17:19], "big")
        d["minor"] = int.from_bytes(data[19:21], "big")
        d["measured_power"] = int.from_bytes(data[21:22], "big", signed=True)
        d.update(_params(data[22:]))
    elif t == FRAME_UID and len(data) >= 23:
        d["namespace"] = data[1:11].hex()
        d["instance"] = data[11:17].hex()
        d["measured_power"] = int.from_bytes(data[17:18], "big", signed=True)
        d.update(_params(data[18:]))
    elif t == FRAME_URL and len(data) >= 25:
        d["url"] = decode_url(data[1:19])
        d["measured_power"] = int.from_bytes(data[19:20], "big", signed=True)
        d.update(_params(data[20:]))
    elif t == FRAME_TLM and len(data) >= 6:
        d.update(_params(data[1:]))
    elif t == FRAME_ACC and len(data) >= 6:
        # ACC (accelerometer) frame. No fields of its own - just the common
        # interval/TX/trigger trailer, like TLM.
        d.update(_params(data[1:]))
    elif t == FRAME_USER and len(data) >= 28:
        # User-defined data frame: arbitrary bytes (set via USER_FIELD_DATA),
        # then the common interval/TX/trigger trailer.
        d["data"] = data[1:23].hex()
        d.update(_params(data[23:]))
    return d


def parse_device_info(data: bytes) -> dict:
    strings = [s.decode(errors="replace") for s in data[9:].split(b"\x00") if s]
    keys = ["manufacturer", "chip", "model", "firmware", "hardware"]
    info = {
        "battery_mV": int.from_bytes(data[1:3], "little"),
        "mac": ":".join(f"{b:02X}" for b in data[3:9]),
    }
    info.update(dict(zip(keys, strings)))
    if len(strings) > len(keys):
        info["extra"] = strings[len(keys):]
    return info


# --------------------------------------------------------------------------
# Beacon session
# --------------------------------------------------------------------------

class DXBeacon:
    def __init__(self, client: BleakClient, verbose: bool = False):
        self.client = client
        self.verbose = verbose
        self.queue: asyncio.Queue = asyncio.Queue()
        self.notify_char = self.cmd_char = self.pwd_char = None

    def _find_chars(self):
        for svc in self.client.services:
            if svc.uuid.lower()[4:8] in STANDARD_SERVICES and svc.uuid.lower().endswith("-0000-1000-8000-00805f9b34fb"):
                continue
            chars = sorted(svc.characteristics, key=lambda c: c.handle)
            notify = [c for c in chars if "notify" in c.properties]
            writes = [c for c in chars if c not in notify and
                      ("write" in c.properties or "write-without-response" in c.properties)]
            if notify and len(writes) >= 2:
                # In handle order: notify (0x001d), command (0x0021), password (0x0024)
                self.notify_char, self.cmd_char, self.pwd_char = notify[0], writes[0], writes[1]
                if self.verbose:
                    print(f"service  {svc.uuid}")
                    print(f"notify   {self.notify_char.uuid}")
                    print(f"command  {self.cmd_char.uuid}")
                    print(f"password {self.pwd_char.uuid}")
                return
        raise ProtocolError("Config service not found - run 'discover' to inspect the GATT table")

    def _on_notify(self, _char, data: bytearray):
        self.queue.put_nowait(bytes(data))

    async def setup(self):
        self._find_chars()
        await self.client.start_notify(self.notify_char, self._on_notify)

    async def send(self, cmd: int, data: bytes = b"", expect_reply: bool = True,
                   timeout: float = 2.0):
        while not self.queue.empty():
            self.queue.get_nowait()
        frame = build_frame(cmd, data)
        if self.verbose:
            print(f">> {frame.hex()}")
        await self.client.write_gatt_char(self.cmd_char, frame, response=True)
        if not expect_reply:
            await asyncio.sleep(0.15)
            return None
        try:
            reply = await asyncio.wait_for(self.queue.get(), timeout)
        except asyncio.TimeoutError:
            raise ProtocolError(f"No reply to command 0x{cmd:02x}")
        if self.verbose:
            print(f"<< {reply.hex()}")
        await asyncio.sleep(0.05)
        return reply

    async def send_ack(self, cmd: int, data: bytes = b""):
        reply = await self.send(cmd, data)
        if reply != build_frame(cmd, b"\x01"):
            raise ProtocolError(f"Unexpected reply to 0x{cmd:02x}: {reply.hex()}")

    async def authenticate(self, password: str):
        await self.send(CMD_PREAUTH)
        if self.verbose:
            print(f">> password {password!r}")
        await self.client.write_gatt_char(self.pwd_char, password.encode(), response=True)
        await asyncio.sleep(0.1)

    # ---- reads ----

    async def read_slots(self) -> list:
        return list(await self.send(SLOT_SELECT_BASE))

    async def read_frame(self, frame_type: int) -> dict:
        return parse_frame(await self.send(frame_type))

    async def read_device_info(self) -> dict:
        return parse_device_info(await self.send(CMD_DEVICE_INFO))

    # ---- writes ----

    async def _resolve_trigger(self, read_cmd, trigger, trigger_seconds):
        # trigger=None keeps whatever trigger is currently set. Passing a type
        # code (see TRIGGER_NAMES) changes it; 0 ("off") clears it.
        # trigger_seconds is how long the beacon advertises once triggered, 1-100.
        # 0xA1 ("read trigger") returns junk - the frame's own trailer is the
        # only reliable way to read the current trigger back.
        if trigger is None:
            cur = parse_frame(await self.send(read_cmd))
            trigger = TRIGGER_CODES.get(cur.get("trigger"), 0)
            trigger_seconds = cur.get("trigger_seconds", DEFAULT_TRIGGER_SECONDS)
        elif trigger_seconds is None:
            trigger_seconds = DEFAULT_TRIGGER_SECONDS
        return trigger, trigger_seconds

    async def _save(self, trigger, trigger_seconds):
        if trigger:
            await self.send_ack(CMD_SET_TRIGGER, bytes([trigger, trigger_seconds]))
            await self.send(CMD_READ_TRIGGER)  # app always reads it back here; reply is junk,
                                                # but the firmware seems to need this call before
                                                # CMD_APPLY or the trigger doesn't actually
                                                # commit. Ignore the reply.
        else:
            await self.send_ack(CMD_SAVE)

    async def set_acc(self, slot, interval, tx, trigger=None, trigger_seconds=None):
        # ACC (accelerometer) frame. Like TLM it has no fields beyond the
        # common trailer, but it's written through its own opcodes rather
        # than TLM's (there's no capture of TLM being written at all).
        trigger, trigger_seconds = await self._resolve_trigger(FRAME_ACC, trigger, trigger_seconds)
        await self.send_ack(SLOT_SELECT_BASE + slot)
        await self.send(FRAME_ACC, expect_reply=False)  # set slot frame type
        await self.send_ack(ACC_FIELD_INTERVAL, bytes([interval]))
        await self.send_ack(ACC_FIELD_TX_POWER, bytes([tx]))
        await self._save(trigger, trigger_seconds)
        await self.send_ack(CMD_APPLY)

    async def set_user(self, slot, data, interval, tx, trigger=None, trigger_seconds=None):
        # User-defined data frame: an arbitrary byte string (22 bytes max,
        # firmware zero-pads), plus the usual interval/TX/trigger trailer.
        trigger, trigger_seconds = await self._resolve_trigger(FRAME_USER, trigger, trigger_seconds)
        await self.send_ack(SLOT_SELECT_BASE + slot)
        await self.send(FRAME_USER, expect_reply=False)  # set slot frame type
        await self.send_ack(USER_FIELD_DATA, data)
        await self.send_ack(USER_FIELD_INTERVAL, bytes([interval]))
        await self.send_ack(USER_FIELD_TX_POWER, bytes([tx]))
        await self._save(trigger, trigger_seconds)
        await self.send_ack(CMD_APPLY)

    async def set_name(self, slot, name, interval, tx, trigger=None, trigger_seconds=None):
        trigger, trigger_seconds = await self._resolve_trigger(FRAME_DEVICE_NAME, trigger, trigger_seconds)
        await self.send_ack(SLOT_SELECT_BASE + slot)
        await self.send(FRAME_DEVICE_NAME, expect_reply=False)  # set slot frame type
        await self.send_ack(NAME_FIELD_NAME, name.encode())
        await self.send_ack(NAME_FIELD_INTERVAL, bytes([interval]))
        await self.send_ack(NAME_FIELD_TX_POWER, bytes([tx]))
        await self._save(trigger, trigger_seconds)
        await self.send_ack(CMD_APPLY)

    async def set_ibeacon(self, slot, uuid, major, minor, mpower, interval, tx,
                           trigger=None, trigger_seconds=None):
        trigger, trigger_seconds = await self._resolve_trigger(FRAME_IBEACON, trigger, trigger_seconds)
        await self.send_ack(SLOT_SELECT_BASE + slot)
        await self.send(FRAME_IBEACON, expect_reply=False)  # set slot frame type
        await self.send_ack(IBEACON_FIELD_UUID, uuid)
        await self.send_ack(IBEACON_FIELD_MAJOR, major.to_bytes(2, "big"))
        await self.send_ack(IBEACON_FIELD_MINOR, minor.to_bytes(2, "big"))
        await self.send_ack(IBEACON_FIELD_MPOWER, mpower.to_bytes(1, "big", signed=True))
        await self.send_ack(IBEACON_FIELD_INTERVAL, bytes([interval]))
        await self.send_ack(IBEACON_FIELD_TX_POWER, bytes([tx]))
        await self._save(trigger, trigger_seconds)
        await self.send_ack(CMD_APPLY)

    async def set_uid(self, slot, namespace, instance, mpower, interval, tx,
                       trigger=None, trigger_seconds=None):
        trigger, trigger_seconds = await self._resolve_trigger(FRAME_UID, trigger, trigger_seconds)
        await self.send_ack(SLOT_SELECT_BASE + slot)
        await self.send(FRAME_UID, expect_reply=False)
        await self.send_ack(UID_FIELD_NAMESPACE, namespace)
        await self.send_ack(UID_FIELD_INSTANCE, instance)
        await self.send_ack(UID_FIELD_MPOWER, mpower.to_bytes(1, "big", signed=True))
        await self.send_ack(UID_FIELD_INTERVAL, bytes([interval]))
        await self.send_ack(UID_FIELD_TX_POWER, bytes([tx]))
        await self._save(trigger, trigger_seconds)
        await self.send_ack(CMD_APPLY)

    async def delete_slot(self, slot):
        await self.send(FRAME_EMPTY)                       # app always sends this first
        await self.send_ack(SLOT_SELECT_BASE + slot)
        await self.send(FRAME_EMPTY, expect_reply=False)   # set frame type = empty
        await self.send_ack(CMD_APPLY)

    async def set_password(self, new):
        await self.send_ack(CMD_SET_PASSWORD, new.encode())
        await self.send_ack(CMD_APPLY)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def hexbytes(s: str, length: int = None) -> bytes:
    b = bytes.fromhex(s.replace("-", "").replace(":", "").replace(" ", ""))
    if length is not None and len(b) != length:
        raise argparse.ArgumentTypeError(f"expected {length} bytes, got {len(b)}")
    return b


def print_dict(d: dict, indent: str = "  "):
    for k, v in d.items():
        print(f"{indent}{k:15} {v}")


async def cmd_scan(args):
    found = await BleakScanner.discover(timeout=args.timeout, return_adv=True)
    for dev, adv in sorted(found.values(), key=lambda x: -x[1].rssi):
        name = adv.local_name or dev.name or ""
        is_dx = "CP27" in name.upper() or "DX" in name.upper() or dev.address.upper().startswith(DX_OUI)
        if args.all or is_dx:
            print(f"{dev.address}  {adv.rssi:4d} dBm  {name}")


async def cmd_discover(client):
    for svc in client.services:
        print(f"Service {svc.uuid}  ({svc.description})")
        for c in svc.characteristics:
            print(f"  Char 0x{c.handle:04x} {c.uuid}  [{', '.join(c.properties)}]")
            for desc in c.descriptors:
                line = f"    Desc 0x{desc.handle:04x} {desc.uuid}"
                if desc.uuid.lower().startswith("00002901"):
                    try:
                        val = await client.read_gatt_descriptor(desc.handle)
                        line += f"  = {bytes(val).decode(errors='replace')!r}"
                    except Exception as e:
                        line += f"  (read failed: {e})"
                print(line)


async def cmd_read(b: DXBeacon):
    slots = await b.read_slots()
    print("Slots:")
    for i, t in enumerate(slots, 1):
        print(f"  {i}: {FRAME_NAMES.get(t, f'0x{t:02x}')}")
    for t in dict.fromkeys(s for s in slots if s != FRAME_EMPTY):
        print(f"\nFrame 0x{t:02x}:")
        print_dict(await b.read_frame(t))
    print("\nDevice info:")
    print_dict(await b.read_device_info())
    print(f"\nStatus (0x{CMD_STATUS:02x}): {(await b.send(CMD_STATUS)).hex()}")


def _on_disconnect(_client):
    print("!! disconnected", file=sys.stderr)


async def run(args):
    if args.command == "scan":
        return await cmd_scan(args)

    if args.verbose:
        print(f">> connecting to {args.address}")
    disconnected_cb = _on_disconnect if args.verbose else None
    async with BleakClient(args.address, timeout=20.0,
                           disconnected_callback=disconnected_cb) as client:
        if args.verbose:
            print("<< connected")
        if args.command == "discover":
            return await cmd_discover(client)

        b = DXBeacon(client, args.verbose)
        await b.setup()
        await b.authenticate(args.password)
        # Confirm the password worked before doing anything else
        try:
            await b.read_slots()
        except (ProtocolError, BleakError, EOFError, OSError):
            raise AuthError(args.password)

        if args.command == "read":
            await cmd_read(b)

        elif args.command == "set-ibeacon":
            cur = {}
            try:
                cur = await b.read_frame(FRAME_IBEACON)
            except ProtocolError:
                pass
            def pick(name, given, conv=lambda x: x):
                if given is not None:
                    return given
                if name in cur:
                    return conv(cur[name])
                sys.exit(f"--{name.replace('_', '-')} is required (no existing iBeacon frame to copy from)")
            uuid = args.uuid if args.uuid is not None else pick("uuid", None, lambda u: hexbytes(u, 16))
            trigger = TRIGGER_CODES[args.trigger] if args.trigger is not None else None
            await b.set_ibeacon(args.slot, uuid,
                                pick("major", args.major), pick("minor", args.minor),
                                pick("measured_power", args.measured_power),
                                pick("interval", args.interval), pick("tx_power", args.tx_power),
                                trigger=trigger, trigger_seconds=args.trigger_seconds)
            print("Done. New iBeacon frame:")
            print_dict(await b.read_frame(FRAME_IBEACON))

        elif args.command == "set-trigger":
            slots = await b.read_slots()
            frame_type = slots[args.slot - 1]
            trigger = TRIGGER_CODES[args.trigger]
            if frame_type == FRAME_DEVICE_NAME:
                cur = await b.read_frame(FRAME_DEVICE_NAME)
                await b.set_name(args.slot, cur["name"], cur["interval"], cur["tx_power"],
                                 trigger=trigger, trigger_seconds=args.seconds)
            elif frame_type == FRAME_ACC:
                cur = await b.read_frame(FRAME_ACC)
                await b.set_acc(args.slot, cur["interval"], cur["tx_power"],
                                trigger=trigger, trigger_seconds=args.seconds)
            elif frame_type == FRAME_IBEACON:
                cur = await b.read_frame(FRAME_IBEACON)
                await b.set_ibeacon(args.slot, hexbytes(cur["uuid"], 16),
                                    cur["major"], cur["minor"], cur["measured_power"],
                                    cur["interval"], cur["tx_power"],
                                    trigger=trigger, trigger_seconds=args.seconds)
            elif frame_type == FRAME_UID:
                cur = await b.read_frame(FRAME_UID)
                await b.set_uid(args.slot, hexbytes(cur["namespace"]), hexbytes(cur["instance"]),
                                cur["measured_power"], cur["interval"], cur["tx_power"],
                                trigger=trigger, trigger_seconds=args.seconds)
            elif frame_type == FRAME_USER:
                cur = await b.read_frame(FRAME_USER)
                await b.set_user(args.slot, hexbytes(cur["data"]), cur["interval"], cur["tx_power"],
                                 trigger=trigger, trigger_seconds=args.seconds)
            else:
                sys.exit(f"Slot {args.slot} is {FRAME_NAMES.get(frame_type, f'0x{frame_type:02x}')} "
                         "- trigger is only supported on device-name, iBeacon, Eddystone-UID, "
                         "ACC and User frames")
            print(f"Trigger set to {args.trigger!r}. New frame:")
            print_dict(await b.read_frame(frame_type))

        elif args.command == "set-acc":
            cur = {}
            try:
                cur = await b.read_frame(FRAME_ACC)
            except ProtocolError:
                pass
            def pick(name, given, conv=lambda x: x):
                if given is not None:
                    return given
                if name in cur:
                    return conv(cur[name])
                sys.exit(f"--{name.replace('_', '-')} is required (no existing ACC frame to copy from)")
            trigger = TRIGGER_CODES[args.trigger] if args.trigger is not None else None
            await b.set_acc(args.slot, pick("interval", args.interval), pick("tx_power", args.tx_power),
                            trigger=trigger, trigger_seconds=args.trigger_seconds)
            print("Done. New ACC frame:")
            print_dict(await b.read_frame(FRAME_ACC))

        elif args.command == "set-name":
            cur = {}
            try:
                cur = await b.read_frame(FRAME_DEVICE_NAME)
            except ProtocolError:
                pass
            def pick(name, given, conv=lambda x: x):
                if given is not None:
                    return given
                if name in cur:
                    return conv(cur[name])
                sys.exit(f"--{name.replace('_', '-')} is required (no existing device-name frame to copy from)")
            if args.name is not None and len(args.name.encode()) > 28:
                sys.exit("name is too long (28 bytes max)")
            trigger = TRIGGER_CODES[args.trigger] if args.trigger is not None else None
            await b.set_name(args.slot, pick("name", args.name),
                             pick("interval", args.interval), pick("tx_power", args.tx_power),
                             trigger=trigger, trigger_seconds=args.trigger_seconds)
            print("Done. New device-name frame:")
            print_dict(await b.read_frame(FRAME_DEVICE_NAME))

        elif args.command == "set-uid":
            cur = {}
            try:
                cur = await b.read_frame(FRAME_UID)
            except ProtocolError:
                pass
            def pick(name, given, conv=lambda x: x):
                if given is not None:
                    return given
                if name in cur:
                    return conv(cur[name])
                sys.exit(f"--{name.replace('_', '-')} is required (no existing UID frame to copy from)")
            trigger = TRIGGER_CODES[args.trigger] if args.trigger is not None else None
            await b.set_uid(args.slot,
                            pick("namespace", args.namespace, lambda h: hexbytes(h, 10)),
                            pick("instance", args.instance, lambda h: hexbytes(h, 6)),
                            pick("measured_power", args.measured_power),
                            pick("interval", args.interval), pick("tx_power", args.tx_power),
                            trigger=trigger, trigger_seconds=args.trigger_seconds)
            print("Done. New UID frame:")
            print_dict(await b.read_frame(FRAME_UID))

        elif args.command == "set-user":
            cur = {}
            try:
                cur = await b.read_frame(FRAME_USER)
            except ProtocolError:
                pass
            def pick(name, given, conv=lambda x: x):
                if given is not None:
                    return given
                if name in cur:
                    return conv(cur[name])
                sys.exit(f"--{name.replace('_', '-')} is required (no existing User frame to copy from)")
            if args.data is not None and len(hexbytes(args.data)) > 22:
                sys.exit("data is too long (22 bytes max)")
            trigger = TRIGGER_CODES[args.trigger] if args.trigger is not None else None
            await b.set_user(args.slot, pick("data", args.data, hexbytes),
                             pick("interval", args.interval), pick("tx_power", args.tx_power),
                             trigger=trigger, trigger_seconds=args.trigger_seconds)
            print("Done. New User frame:")
            print_dict(await b.read_frame(FRAME_USER))

        elif args.command == "delete-slot":
            await b.delete_slot(args.slot)
            print("Slots now:", " ".join(f"{t:02x}" for t in await b.read_slots()))

        elif args.command == "set-password":
            if len(args.new_password) != 6:
                print("Warning: the app only ever used 6-character passwords", file=sys.stderr)
            await b.set_password(args.new_password)
            print(f"Password changed to {args.new_password!r}")

        elif args.command == "factory-reset":
            if not args.yes:
                sys.exit("This resets all settings and the password. Re-run with --yes to confirm.")
            try:
                await b.send_ack(CMD_FACTORY_RESET)
            except Exception:
                pass  # link may drop before/after the ack, same as power-off
            print("Factory reset sent.")

        elif args.command == "power-off":
            if not args.yes:
                sys.exit("The beacon will need its button pressed to power back on. Re-run with --yes.")
            try:
                await b.send_ack(CMD_POWER_OFF)
            except Exception:
                pass  # link may drop before/after the ack
            print("Power-off sent.")

        elif args.command == "raw":
            data = hexbytes(args.data) if args.data else b""
            reply = await b.send(int(args.cmd, 16), data, expect_reply=not args.no_reply)
            print("Reply:", reply.hex() if reply is not None else "(none expected)")


def main():
    env_password = os.environ.get("DXBEACON_PASSWORD", DEFAULT_PASSWORD)

    # Common options, accepted both before and after the subcommand.
    # A fresh parser is built each time so the action objects aren't shared.
    def common():
        c = argparse.ArgumentParser(add_help=False)
        c.add_argument("-a", "--address", default=argparse.SUPPRESS,
                       help="beacon BLE address (from 'scan')")
        c.add_argument("-p", "--password", default=argparse.SUPPRESS,
                       help="beacon password (default: $DXBEACON_PASSWORD, else dx1234)")
        c.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
                       help="show raw frames")
        return c

    p = argparse.ArgumentParser(description="Configure DX-Smart CP27 beacons over BLE",
                                parents=[common()])
    p.set_defaults(address=None, password=env_password, verbose=False)
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, **kw):
        return sub.add_parser(name, parents=[common()], **kw)

    s = add("scan", help="find nearby beacons")
    s.add_argument("--all", action="store_true", help="show all BLE devices")
    s.add_argument("--timeout", type=float, default=5.0)

    add("discover", help="dump GATT table and characteristic descriptions")
    add("read", help="read and decode all slots and device info")

    s = add("set-ibeacon", help="write an iBeacon frame (unspecified fields keep current values)")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("--uuid", type=lambda x: hexbytes(x, 16))
    s.add_argument("--major", type=int)
    s.add_argument("--minor", type=int)
    s.add_argument("--measured-power", type=int, help="RSSI at 1 m, e.g. -57")
    s.add_argument("--interval", type=int, help="raw adv interval index")
    s.add_argument("--tx-power", type=int, choices=range(0, 8), help="global TX power level 0-7")
    s.add_argument("--trigger", choices=sorted(TRIGGER_CODES),
                   help="trigger action (unspecified keeps the current one)")
    s.add_argument("--trigger-seconds", type=int, default=None, choices=range(1, 101),
                   metavar="1-100",
                   help=f"advertising duration once triggered (default: {DEFAULT_TRIGGER_SECONDS})")

    s = add("set-trigger",
            help="set or clear the trigger action on a device-name, iBeacon, Eddystone-UID, "
                 "ACC or User slot")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("trigger", choices=sorted(TRIGGER_CODES))
    s.add_argument("--seconds", type=int, default=DEFAULT_TRIGGER_SECONDS, choices=range(1, 101),
                   metavar="1-100",
                   help=f"advertising duration once triggered (default: {DEFAULT_TRIGGER_SECONDS})")

    s = add("set-name", help="write the device-name frame (unspecified fields keep current values)")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("--name", help="advertised name, 28 bytes max")
    s.add_argument("--interval", type=int, help="raw adv interval index")
    s.add_argument("--tx-power", type=int, choices=range(0, 8), help="global TX power level 0-7")
    s.add_argument("--trigger", choices=sorted(TRIGGER_CODES),
                   help="trigger action (unspecified keeps the current one)")
    s.add_argument("--trigger-seconds", type=int, default=None, choices=range(1, 101),
                   metavar="1-100",
                   help=f"advertising duration once triggered (default: {DEFAULT_TRIGGER_SECONDS})")

    s = add("set-acc",
            help="write the ACC (accelerometer) frame - has no fields beyond interval/TX/trigger")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("--interval", type=int, help="raw adv interval index")
    s.add_argument("--tx-power", type=int, choices=range(0, 8), help="global TX power level 0-7")
    s.add_argument("--trigger", choices=sorted(TRIGGER_CODES),
                   help="trigger action (unspecified keeps the current one)")
    s.add_argument("--trigger-seconds", type=int, default=None, choices=range(1, 101),
                   metavar="1-100",
                   help=f"advertising duration once triggered (default: {DEFAULT_TRIGGER_SECONDS})")

    s = add("set-user",
            help="write the User (arbitrary data) frame (unspecified fields keep current values)")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("--data", help="user data as hex, 22 bytes max")
    s.add_argument("--interval", type=int, help="raw adv interval index")
    s.add_argument("--tx-power", type=int, choices=range(0, 8), help="global TX power level 0-7")
    s.add_argument("--trigger", choices=sorted(TRIGGER_CODES),
                   help="trigger action (unspecified keeps the current one)")
    s.add_argument("--trigger-seconds", type=int, default=None, choices=range(1, 101),
                   metavar="1-100",
                   help=f"advertising duration once triggered (default: {DEFAULT_TRIGGER_SECONDS})")

    s = add("set-uid", help="write an Eddystone-UID frame")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("--namespace", type=lambda x: hexbytes(x, 10))
    s.add_argument("--instance", type=lambda x: hexbytes(x, 6))
    s.add_argument("--measured-power", type=int, help="RSSI at 0 m, e.g. -24")
    s.add_argument("--interval", type=int)
    s.add_argument("--tx-power", type=int, choices=range(0, 8))
    s.add_argument("--trigger", choices=sorted(TRIGGER_CODES),
                   help="trigger action (unspecified keeps the current one)")
    s.add_argument("--trigger-seconds", type=int, default=None, choices=range(1, 101),
                   metavar="1-100",
                   help=f"advertising duration once triggered (default: {DEFAULT_TRIGGER_SECONDS})")

    s = add("delete-slot", help="clear a slot")
    s.add_argument("slot", type=int, choices=range(1, 8))

    s = add("set-password", help="change the connection password")
    s.add_argument("new_password")

    s = add("factory-reset", help="reset all settings and password")
    s.add_argument("--yes", action="store_true")

    s = add("power-off", help="power the beacon off")
    s.add_argument("--yes", action="store_true")

    s = add("raw", help="send an arbitrary command, e.g. raw 64 or raw 91 6578616d706c65")
    s.add_argument("cmd", help="command byte in hex")
    s.add_argument("data", nargs="?", help="data bytes in hex")
    s.add_argument("--no-reply", action="store_true", help="don't wait for a notification")

    args = p.parse_args()
    if args.command != "scan" and not args.address:
        p.error("--address is required (run 'scan' first)")
    try:
        asyncio.run(run(args))
    except AuthError as e:
        if args.verbose:
            traceback.print_exc()
        sys.exit(f"Authentication failed with password {e.args[0]!r}. If you changed it, "
                 f"pass the current one with -p NEWPASS or set DXBEACON_PASSWORD.")
    except ProtocolError as e:
        if args.verbose:
            traceback.print_exc()
        sys.exit(f"Protocol error: {e}")
    except (BleakError, asyncio.TimeoutError) as e:
        if args.verbose:
            traceback.print_exc()
        sys.exit(f"Bluetooth error: {e or type(e).__name__}")


if __name__ == "__main__":
    main()
