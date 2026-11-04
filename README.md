## Discovered DX-CP27 configuration protocol by monitoring DX_SMART

The file btsnnop_hic.log shows the packets exchanged between the DX-SMART app and the DX-CP27 beacon.
It can be viewed in Wireshark.

The file snooped_conversation.txt is the extracted commands/responses from that log.

The file snooped_data.txt is the extracted data from that log.

### Reading the packet lengths

The Length column includes 9 bytes of overhead: the HCI packet type, the ACL header and the L2CAP header.
You can check this against two packets whose sizes are known. 
The MTU exchange is a 3-byte ATT PDU and shows as 12. 
A Write Response is 1 byte and shows as 10. 
To get the actual application data, subtract 9 for the ATT PDU, then subtract another 3 for the 
opcode and handle on writes and notifications. 
So a 17-byte Write Request carries 5 bytes of data, and an 18-byte notification carries 6 bytes.

### Connection setup

The beacon asks for an MTU of 256 and the phone offers 517, so the negotiated MTU is 256. 
The phone then asks for a Database Hash, and the beacon doesn’t support it. 
That means there’s no GATT caching, which is why the app does a full service discovery every 
time it connects.

### The GATT table looks like this:

    Handles	        Service	            Notes
    0x0001–0x0005	GAP	                Device Name, Appearance
    0x0006–0x0009	GATT	            Service Changed + CCCD
    0x000a–0x000d	Battery	            Battery Level (notifiable)
    0x000e–0x001a	Device Information	Manufacturer, Model, Firmware/Hardware revision, System ID, PnP ID
    0x001b–0x0025	Custom (vendor)	    The config protocol lives here

The custom service has three characteristics.
I’ve inferred their handles from where the discovery steps stopped and from the descriptors it found:
    0x001d is a notify characteristic. Its CCCD is at 0x001e and it has a user description at 0x001f. This is the response channel.
    0x0021 is writable and has a user description at 0x0022. This is the command channel.
    0x0024 is writable and has a user description at 0x0025. It’s for authentication (see below).

### The protocol pattern

The protocol is a simple request/response scheme: the app writes a command to 0x0021, 
and the beacon answers with a notification on 0x001d about 1 ms after the write response.

The app writes to the CCCD at 0x001e to enable notifications. 
Then it sends two commands to 0x0021 and gets 6-byte replies. 
These look like an unauthenticated handshake or a device-info query.

The app writes 6 bytes to 0x0024, once. 
I strongly suspect this is the password: DX-Smart beacons ship with a 6-digit default password, 
commonly 666666. Everything after this point looks like authenticated configuration traffic.

The app sends a burst of 5-byte commands, and the replies vary in size: 6, 34, 27, 23, 25, 6, 3 
and 61 bytes of data. This pattern suggests the app is reading the current config parameter by 
parameter. Each command is probably a “get parameter N” opcode, and the reply carries that 
parameter’s value. The longer replies could hold a 16-byte iBeacon UUID, a device name or an 
Eddystone URL.

Later, the write sizes change: 24, 10, 10, 9 and 9 bytes. Every reply is 6 bytes. 
This looks like writing parameters, with a fixed-size ACK or status reply each time. 
The 24-byte write is a good candidate for setting a UUID, since 16 bytes of UUID plus a header 
would fit. There are two places where a write gets a Write Response but no notification. 
That could mean those commands don’t send an acknowledgement.

The scattered pairs of commands, plus the single commands later on, are probably the app 
re-reading values after a save or refreshing its UI.

### Here’s the discovered command reference:

    Cmd	      Function	             Data
    0x10	  Read slot table	     Reply: 7 bytes, each a frame type or FF for empty
    0x11–0x17 Select slot 1–7	     none
    0x21	  Factory reset	         none
    0x22	  Status (unknown)	     Reply: 01 01 01
    0x23	  Power off	             none
    0x24	  Change password	     ASCII password
    0x25	  Pre-auth check	     none
    0x30	  Device info	         Reply: battery (mV, LE), MAC, manufacturer, chip, model, firmware/hardware versions
    0x60	  Apply	                 none
    0x61–0x65 Read frame (outside a slot edit) / set frame type (after select)
                                     none
    0x66	  Read/set ACC (accelerometer) frame  none (see Frame types below)
    0x67	  Read/set User (arbitrary data) frame  none (see Frame types below)
    0x71	  Device name	         ASCII, variable length (28 bytes max, firmware zero-pads)
    0x72	  Device name adv interval  1 byte
    0x73	  Device name TX power (global)  1 byte, 0–7
    0x74	  iBeacon UUID	         16 bytes
    0x75	  iBeacon major	         2 bytes, big-endian
    0x76	  iBeacon minor	         2 bytes, big-endian
    0x77	  iBeacon measured power 1 byte, signed dBm (==power at 1mtr, use for distance estimate)
    0x78	  iBeacon adv interval	 1 byte
    0x79	  TX power (global)	     1 byte, 0–7
    0x81	  UID namespace	         10 bytes
    0x82	  UID instance	         6 bytes
    0x83	  UID measured power	 1 byte, signed dBm
    0x84	  UID adv interval	     1 byte, 100mS steps, eg. 3==300mS
    0x85	  TX power (global)	     1 byte, 0..7 steps across -19.5dBm..+2.5dBm
    0x93	  ACC frame adv interval   1 byte
    0x94	  ACC frame TX power	 1 byte, 0–7
    0x95	  User frame data	     ASCII/hex, variable length (22 bytes max, firmware zero-pads)
    0x96	  User frame adv interval  1 byte
    0x97	  User frame TX power	 1 byte, 0–7
    0xA0	  Save	                 none
    0xA1	  Read trigger	         Reply: 2 bytes, trigger type + advertising duration (seconds)
    0xA2	  Set trigger	         Data: 2 bytes, trigger type + advertising duration (seconds)
    0xFF	  Pre-edit query / set slot empty (after select)
                                     none

### Trigger (0xA1 / 0xA2)

Discovered from a capture that set an iBeacon slot's trigger to each of its four options in turn:
double-click, triple-click, device-move, then off. The trigger fires a one-shot advertisement on
that event; the second data byte is how long it then advertises, in seconds.

0xA2 is "save with trigger enabled." It takes the place of the 0xA0 save in the edit sequence
(select slot, resend all iBeacon fields 0x74-0x79, then this, then 0x60 apply) and carries two
data bytes, mode and seconds:

    4e4f a2 02 <mode> <seconds> <chk>

    Write          Mode   What it set
    a2 02 01 1e    01     double-click
    a2 02 02 1e    02     triple-click
    a2 02 03 1e    03     device-move

The seconds byte (0x1e = 30) was only entered once via the app UI (on the double-click edit), so
it was simply resent unchanged for the later modes - it's a genuine field, not a fixed constant.

0xA0 is "save with trigger disabled": the final "off" edit ran the identical field sequence but
ended with a plain 0xA0 instead of 0xA2, and the trigger turned off. So 0xA0 and 0xA2 are two
forms of the same save step - 0xA2 enables the trigger, 0xA0 clears it.

0xA1 reads the trigger config outside of an edit session (`4e4f a1 00`) and returns 2 raw bytes,
mode and seconds, matching whatever 0xA2 last wrote.

The iBeacon frame's "reserved" trailer is the trigger state, not padding: enabled flag, mode,
seconds. E.g. in the 0x62 reads: `...03 02 00 00 00` is off, `...03 02 01 01 1e` is on/double-click/30s.
So the full trailer is: adv interval, global TX power, trigger-enabled, trigger-mode, trigger-seconds.

    Mode  Meaning
    0x00  off (via 0xA0 save, no 0xA2 call)
    0x01  double-click
    0x02  triple-click
    0x03  device-move

Note: round-tripping this live (write via 0xA2, then read back via 0xA1 or the 0x62 frame) hasn't
been fully reliable in testing - sometimes the just-written value reads back correctly after a
reconnect, sometimes it doesn't. Not yet confirmed whether this is a timing issue (the beacon
needs longer to persist to flash than our apply ack suggests) or whether 0xA1 reflects the state
of the last-fired trigger event rather than the stored configuration.

Update: live testing confirmed the fix - the app's own sequence calls 0xA1 (ignoring its reply)
between 0xA2 and the 0x60 apply, and without that call the trigger change doesn't commit. With it,
writes verified reliably via the frame trailer across multiple reconnects. dxbeacon.py's
set_ibeacon()/set_uid() both do this now.

The capture only ever exercised this on an iBeacon slot. Eddystone-UID frames (0x63) share the
same trailer layout (interval, TX power, trigger-enabled, trigger-mode, trigger-seconds - see
_params in dxbeacon.py) and the same 0xA0/0xA1/0xA2 save commands, so dxbeacon.py applies the
identical trigger logic to `set-uid`/`set-trigger` on UID slots by symmetry. This hasn't been
independently confirmed against a UID-specific capture.

Update: a second, independent capture (snooped_data-device-info.txt) set a device-name slot's
(0x61) trigger to double-click/53s using the exact same 0xA2 02 <mode> <seconds> / 0xA1 / 0x60
sequence, confirming the save mechanism isn't iBeacon-specific. dxbeacon.py's `set_name()` and
`set-trigger` now apply it to device-name slots too.

### Two more frame types (ACC / 0x66, and User / 0x67), and a save-failure notification

A capture (snooped_data-frame-type.txt) of the app's frame-type picker turned up two frame type
codes beyond the original five (0x61-0x65):

0x66 is the ACC (accelerometer) frame, confirmed directly by the user's own device: setting a
device-name-only slot's trigger with an ACC frame in another slot made the beacon only become
connectable around a trigger event (e.g. a double-click), rather than continuously - worth knowing
if a slot ever seems to "disappear" after editing. It has no fields of its own - reading it returns
just the common trailer (interval, TX power, trigger), like TLM. It's written through its own
opcodes though: 0x93 sets the interval, 0x94 sets TX power, then the usual 0xA0/0xA2 save and 0x60
apply. dxbeacon.py exposes it as `set-acc`.

0x67 is the User frame: an arbitrary 22-byte data field (set via 0x95), plus the usual interval
(0x96) and TX power (0x97), then the standard 0xA0/0xA2 save and 0x60 apply. The frame-type-picker
capture's attempt to use it was rejected by the firmware (see the save-failure note below) because
the frame type it tried to assign was already in use on another slot - not because 0x67 itself is
invalid. A second capture (snooped_data-with-user.txt), assigning it to an empty slot, applied
cleanly and read back correctly afterwards, confirming the field layout: `data` (0x95, hex, 22 bytes
max, firmware zero-pads), then the common interval/TX/trigger trailer. dxbeacon.py exposes it as
`set-user`.

Save failures show up as a notification on a *different* command byte than the one you sent, with
data 0x00 instead of the usual 0x01: writing 0x60 (apply) after setting a slot to 0x67 got back
`4E4F F1 01 00 F0` instead of the expected `4E4F 60 01 01 60` ack. A second attempt (assigning the
already-used 0x61 device-name type to a second slot) failed the same way with `4E4F F2 01 00 F3`.
Both attempts left the slot unchanged (still empty) when re-read afterwards. This suggests two
things: first, that 0xF1/0xF2 are generic "the save was rejected" notifications rather than echoes
of the command that failed; second, and more useful going forward, that **a frame type can only be
assigned to one slot at a time** - trying to put the same type on a second slot fails outright.
dxbeacon.py doesn't check for this ahead of time; if you hit it, the write functions raise
ProtocolError showing the raw rejection bytes.

### Frame types

0x62 is iBeacon. 
The response breaks down as UUID E2C56DB5-DFFB-48D2-B060-D0F5A71096E0 (Apple’s AirLocate sample 
UUID, a common default), then major, minor, measured power (C7 = −57 dBm), then two parameter bytes, 
then 00 00 00. Your writes map onto it directly:

    Cmd	    Field	        Value written
    0x74	UUID	        16 bytes
    0x75	Major	        0005
    0x76	Minor	        0006
    0x77	Measured power	C7
    0x78	Param A	        03
    0x79	Param B	        06 → 07

0x61 is the device-name frame, confirmed by a later capture (snooped_data-device-info.txt) that
set it directly. It contains the name, zero-padded to 28 bytes, plus the two parameter bytes.
Writing it uses 0x71 (name, sent as whatever length was typed - the firmware does the zero-padding
on its own), 0x72 (adv interval) and 0x73 (TX power), then the usual 0xA0/0xA2 save and 0x60 apply.

### Commands (phone → beacon, written to 0x0021) look like this:

    4E 4F | CMD | LEN | DATA... | CHK
    4E 4F is the ASCII header “NO”.
    LEN is the number of data bytes.
    CHK is the XOR of CMD, LEN and all the data bytes.

### Write acknowledgements (beacon → phone, notifications on 0x001d) use the same framing:

    4E 4F | CMD | 01 | 01 | CHK. The data byte 01 presumably means success.

### Authentication

The 6 bytes written to 0x0024 are 64 78 31 32 33 34, which is ASCII “dx1234”. 
That’s the password, sent in plaintext, which corrects my earlier guess of 666666. 
No pairing or encryption appears in the capture, so anyone sniffing nearby could capture it.

Command 0x25 is sent before authenticating and returns 01, 
so it’s probably a “connected / auth needed” check.

### Device info (0x30)

The response starts with AE 0B, which is the battery level in millivolts, little-endian: 
0x0BAE = 2990 mV. 
Next comes the MAC address 48:87:2D:9E:42:36, whose OUI matches the “ShenZhenDaXi” vendor that 
Wireshark identified. 
Then come four strings: “DX-SMART”, “Dialog14531” (the DA14531 chip), “CP27”, and the firmware 
version “V2.4.01” and hardware version “V2.4.0”.

### Protocol summary

1. Connect, then enable notifications by writing 01 00 to 0x001e.
2. Send 0x25, an optional pre-auth check.
3. Write the ASCII password to 0x0024. The default is “dx1234”.
4. Send 0x10 to read the slot table, then 0x61–0x65 to read each frame, 
   0x30 for device info and battery, and 0x22 for status.
5. To edit a slot: 0x1N to select it, then the frame type byte (or FF to delete), 
   then the field writes (0x7x for iBeacon, 0x8x for UID), then A0 to save and 60 to apply.
6. Other commands: 0x24 changes the password, 0x21 is a factory reset, and 0x23 disconnects.
