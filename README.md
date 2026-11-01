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
    0x000e–0x001a	Device Information	Manufacturer, Model, FW/SW revision, System ID, PnP ID
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
    0x30	  Device info	         Reply: battery (mV, LE), MAC, manufacturer, chip, model, FW/SW versions
    0x60	  Apply	                 none
    0x61–0x65 Read frame (outside a slot edit) / set frame type (after select)
                                     none
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
    0xA0	  Save	                 none
    0xFF	  Pre-edit query / set slot empty (after select)
                                     none

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

0x61 is probably a device-name frame. 
It contains “CP27-4236”, zero-padded to 28 bytes, plus the two parameter bytes.

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

The response contains AE 0B, which is unknown (perhaps flags or battery). 
Next comes the MAC address 48:87:2D:9E:42:36, whose OUI matches the “ShenZhenDaXi” vendor that 
Wireshark identified. 
Then come four strings: “DX-SMART”, “Dialog14531” (the DA14531 chip), “CP27”, and the version 
strings “V2.4.01” and “V2.4.0”.

### Protocol summary

1. Connect, then enable notifications by writing 01 00 to 0x001e.
2. Send 0x25, an optional pre-auth check.
3. Write the ASCII password to 0x0024. The default is “dx1234”.
4. Send 0x10 to read the slot table, then 0x61–0x65 to read each frame, 
   0x30 for device info and battery, and 0x22 for status.
5. To edit a slot: 0x1N to select it, then the frame type byte (or FF to delete), 
   then the field writes (0x7x for iBeacon, 0x8x for UID), then A0 to save and 60 to apply.
6. Other commands: 0x24 changes the password, 0x21 is a factory reset, and 0x23 disconnects.
