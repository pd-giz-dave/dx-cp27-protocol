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

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

DEFAULT_PASSWORD = "dx1234"
STANDARD_SERVICES = {"1800", "1801", "180a", "180f"}

FRAME_NAMES = {
    0x61: "Device name",
    0x62: "iBeacon",
    0x63: "Eddystone-UID",
    0x64: "Eddystone-URL",
    0x65: "Eddystone-TLM",
    0xFF: "(empty)",
}
URL_SCHEMES = {0: "http://www.", 1: "https://www.", 2: "http://", 3: "https://"}
URL_EXPANSIONS = [".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
                  ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"]

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
    if t == 0x61 and len(data) >= 34:
        d["name"] = data[1:29].rstrip(b"\x00").decode(errors="replace")
        d.update(_params(data[29:]))
    elif t == 0x62 and len(data) >= 27:
        u = data[1:17].hex()
        d["uuid"] = f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}".upper()
        d["major"] = int.from_bytes(data[17:19], "big")
        d["minor"] = int.from_bytes(data[19:21], "big")
        d["measured_power"] = int.from_bytes(data[21:22], "big", signed=True)
        d.update(_params(data[22:]))
    elif t == 0x63 and len(data) >= 23:
        d["namespace"] = data[1:11].hex()
        d["instance"] = data[11:17].hex()
        d["measured_power"] = int.from_bytes(data[17:18], "big", signed=True)
        d.update(_params(data[18:]))
    elif t == 0x64 and len(data) >= 25:
        d["url"] = decode_url(data[1:19])
        d["measured_power"] = int.from_bytes(data[19:20], "big", signed=True)
        d.update(_params(data[20:]))
    elif t == 0x65 and len(data) >= 6:
        d.update(_params(data[1:]))
    return d


def parse_device_info(data: bytes) -> dict:
    strings = [s.decode(errors="replace") for s in data[9:].split(b"\x00") if s]
    keys = ["manufacturer", "chip", "model", "firmware", "software"]
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
        await self.send(0x25)  # pre-auth check, as the app does
        if self.verbose:
            print(f">> password {password!r}")
        await self.client.write_gatt_char(self.pwd_char, password.encode(), response=True)
        await asyncio.sleep(0.1)

    # ---- reads ----

    async def read_slots(self) -> list:
        return list(await self.send(0x10))

    async def read_frame(self, frame_type: int) -> dict:
        return parse_frame(await self.send(frame_type))

    async def read_device_info(self) -> dict:
        return parse_device_info(await self.send(0x30))

    # ---- writes ----

    async def set_ibeacon(self, slot, uuid, major, minor, mpower, interval, tx,
                           trigger=None, trigger_seconds=None):
        # trigger=None keeps whatever trigger is currently set. Passing a type
        # code (see TRIGGER_NAMES) changes it; 0 ("off") clears it.
        # trigger_seconds is how long the beacon advertises once triggered, 1-100.
        # 0xA1 ("read trigger") returns junk - the iBeacon frame's own trailer
        # is the only reliable way to read the current trigger back.
        if trigger is None:
            cur = parse_frame(await self.send(0x62))
            trigger = TRIGGER_CODES.get(cur.get("trigger"), 0)
            trigger_seconds = cur.get("trigger_seconds", DEFAULT_TRIGGER_SECONDS)
        elif trigger_seconds is None:
            trigger_seconds = DEFAULT_TRIGGER_SECONDS

        await self.send_ack(0x10 + slot)
        await self.send(0x62, expect_reply=False)  # set slot frame type
        await self.send_ack(0x74, uuid)
        await self.send_ack(0x75, major.to_bytes(2, "big"))
        await self.send_ack(0x76, minor.to_bytes(2, "big"))
        await self.send_ack(0x77, mpower.to_bytes(1, "big", signed=True))
        await self.send_ack(0x78, bytes([interval]))
        await self.send_ack(0x79, bytes([tx]))
        if trigger:
            await self.send_ack(0xA2, bytes([trigger, trigger_seconds]))  # set trigger + save
            await self.send(0xA1)  # app always reads it back here; reply is junk, but the
                                    # firmware seems to need this call before 0x60 or the
                                    # trigger doesn't actually commit. Ignore the reply.
        else:
            await self.send_ack(0xA0)  # save (also clears any trigger)
        await self.send_ack(0x60)  # apply

    async def set_uid(self, slot, namespace, instance, mpower, interval, tx):
        await self.send_ack(0x10 + slot)
        await self.send(0x63, expect_reply=False)
        await self.send_ack(0x81, namespace)
        await self.send_ack(0x82, instance)
        await self.send_ack(0x83, mpower.to_bytes(1, "big", signed=True))
        await self.send_ack(0x84, bytes([interval]))
        await self.send_ack(0x85, bytes([tx]))
        await self.send_ack(0xA0)
        await self.send_ack(0x60)

    async def delete_slot(self, slot):
        await self.send(0xFF)                       # app always sends this first
        await self.send_ack(0x10 + slot)
        await self.send(0xFF, expect_reply=False)   # set frame type = empty
        await self.send_ack(0x60)

    async def set_password(self, new):
        await self.send_ack(0x24, new.encode())
        await self.send_ack(0x60)


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
        if args.all or "CP27" in name.upper() or "DX" in name.upper():
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
    for t in dict.fromkeys(s for s in slots if s != 0xFF):
        print(f"\nFrame 0x{t:02x}:")
        print_dict(await b.read_frame(t))
    print("\nDevice info:")
    print_dict(await b.read_device_info())
    print(f"\nStatus (0x22): {(await b.send(0x22)).hex()}")


async def run(args):
    if args.command == "scan":
        return await cmd_scan(args)

    async with BleakClient(args.address, timeout=20.0) as client:
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
                cur = await b.read_frame(0x62)
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
            print_dict(await b.read_frame(0x62))

        elif args.command == "set-trigger":
            try:
                cur = await b.read_frame(0x62)
            except ProtocolError:
                sys.exit("No existing iBeacon frame on this slot - set one with 'set-ibeacon' first")
            await b.set_ibeacon(args.slot, hexbytes(cur["uuid"], 16),
                                cur["major"], cur["minor"], cur["measured_power"],
                                cur["interval"], cur["tx_power"],
                                trigger=TRIGGER_CODES[args.trigger], trigger_seconds=args.seconds)
            print(f"Trigger set to {args.trigger!r}. New iBeacon frame:")
            print_dict(await b.read_frame(0x62))

        elif args.command == "set-uid":
            cur = {}
            try:
                cur = await b.read_frame(0x63)
            except ProtocolError:
                pass
            def pick(name, given, conv=lambda x: x):
                if given is not None:
                    return given
                if name in cur:
                    return conv(cur[name])
                sys.exit(f"--{name.replace('_', '-')} is required (no existing UID frame to copy from)")
            await b.set_uid(args.slot,
                            pick("namespace", args.namespace, lambda h: hexbytes(h, 10)),
                            pick("instance", args.instance, lambda h: hexbytes(h, 6)),
                            pick("measured_power", args.measured_power),
                            pick("interval", args.interval), pick("tx_power", args.tx_power))
            print("Done. New UID frame:")
            print_dict(await b.read_frame(0x63))

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
            await b.send_ack(0x21)
            print("Factory reset sent.")

        elif args.command == "power-off":
            if not args.yes:
                sys.exit("The beacon will need its button pressed to power back on. Re-run with --yes.")
            try:
                await b.send_ack(0x23)
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

    s = add("set-trigger", help="set or clear the iBeacon trigger action on a slot")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("trigger", choices=sorted(TRIGGER_CODES))
    s.add_argument("--seconds", type=int, default=DEFAULT_TRIGGER_SECONDS, choices=range(1, 101),
                   metavar="1-100",
                   help=f"advertising duration once triggered (default: {DEFAULT_TRIGGER_SECONDS})")

    s = add("set-uid", help="write an Eddystone-UID frame")
    s.add_argument("--slot", type=int, required=True, choices=range(1, 8))
    s.add_argument("--namespace", type=lambda x: hexbytes(x, 10))
    s.add_argument("--instance", type=lambda x: hexbytes(x, 6))
    s.add_argument("--measured-power", type=int, help="RSSI at 0 m, e.g. -24")
    s.add_argument("--interval", type=int)
    s.add_argument("--tx-power", type=int, choices=range(0, 8))

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
        sys.exit(f"Authentication failed with password {e.args[0]!r}. If you changed it, "
                 f"pass the current one with -p NEWPASS or set DXBEACON_PASSWORD.")
    except ProtocolError as e:
        sys.exit(f"Protocol error: {e}")
    except (BleakError, asyncio.TimeoutError) as e:
        sys.exit(f"Bluetooth error: {e or type(e).__name__}")


if __name__ == "__main__":
    main()
