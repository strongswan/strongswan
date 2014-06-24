# The Versatile IKE Control Interface (VICI) protocol #

The vici plugin implements the server side of an IPC protocol to configure,
monitor and control the IKE daemon charon. It uses request/response and event
messages to communicate over a reliable stream based transport.

## Transport protocol ##

To provide the service, the plugin opens a listening socket using a reliable,
stream based transport. charon relies on the different stream service
abstractions provided by libstrongswan, such as TCP and UNIX sockets.

A client connects to this service to access functionality. It may send an
arbitrary number of packets over the connection before closing it.

To exchange data, the transport protocol is segmented into byte sequences.
Each byte sequence is prefixed by a 32-bit length header in network order,
followed by the data. The maximum segment length is currently limited to 512KB
of data, and the length field contains the length of the data only, not
including the length field itself.

The order of byte sequences must be strict, byte sequences must arrive in the
same order as sent.

## Packet layer ##

Within the byte sequences defined by the transport layer, both the client
and the server can exchange packets. The type of packet defines its structure
and purpose. The packet type is a 8-bit identifier, and is the first byte
in a transport layer byte sequence. The length of the packet is given by the
transport layer.

While a packet type may define the format of the wrapped data freely, currently
all types either contain a name, a message or both. The following packet types
are currently defined:

* _CMD_REQUEST = 0_: A named request message
* _CMD_RESPONSE = 1_: An unnamed response message for a request
* _CMD_UNKNOWN = 2_: An unnamed response if requested command is unknown
* _EVENT_REGISTER = 3_: A named event registration request
* _EVENT_UNREGISTER = 4_: A named event deregistration request
* _EVENT_CONFIRM = 5_: An unnamed response for successful event (de-)registration
* _EVENT_UNKNOWN = 6_: A unnamed response if event (de-)registration failed
* _EVENT = 7_: A named event message

For packets having a named type, after the packet type an 8-bit length header
of the name follows, indicating the string length in bytes of the name tag, not
including the length field itself. The name is an ASCII string that is not
null-terminated.

The rest of the packet forms the exchanged message, the length is determined
by the transport byte sequence length, subtracting the packet type and
the optional name tag in some messages.

### Commands ###

Commands are currently always requested by the client. The server replies with
a response, or with a CMD_UNKNOWN failure message to let the client know
that it does not have a handler for such a command. There is no sequence number
to associate responses to requests, so only one command can be active at
a time on a single connection.

### Events ###

To receive event messages, the client explicitly registers for events by name,
and also unregisters if it does not want to receive events of the named kind
anymore. The server confirms event registration using EVENT_CONFIRM, or
indicates that there is no such event source with EVENT_UNKNOWN.

Events may get raised at any time while registered, even during an active
request command. This mechanism is used to feed continuous data during a request,
for example.

## Message format ##

The defined packet types optionally wrap a message with additional data.
Messages are currently used in CMD_REQUEST/CMD_RESPONSE, and in EVENT packets.
A message uses a hierarchial tree of sections. Each section (or the implicit
root section) contains an arbitrary set of key/value pairs, lists and
sub-sections. The length of a message is not part of the message itself, but
the wrapping layer, usually calculated from the transport byte sequence length.

The message encoding consists of a sequence of elements. Each element starts
with the element type, optionally followed by an element name and/or an element
value. Currently the following message element types are defined:

* _SECTION_START = 0_: Begin a new section having a name
* _SECTION_END = 1_: End a previously started section
* _KEY_VALUE = 2_: Define a value for a named key in the current section
* _LIST_START = 3_: Begin a named list for list items
* _LIST_ITEM = 4_: Define an unnamed item value in the current list
* _LIST_END = 5_: End a previously started list

Types are encoded as 8-bit values. Types having a name (SECTION_START,
KEY_VALUE and LIST_START) have an ASCII string following the type, which itself
uses an 8-bit length header. The string must not be null-terminated, the string
length does not include the length field itself.

Types having a value (KEY_VALUE and LIST_ITEM) have a raw blob sequence,
prefixed with a 16-bit network order length. The blob follows the type or the
name tag if available, the length defined by the length field does not include
the length field itself.

The interpretation of any value is not defined by the message format; it can
take arbitrary blobs. The application may specify types for specific keys, such
as strings or integer representations.

### Sections ###

Sections may be opened in the implicit root section, or any previously section.
They can be nested to arbitrary levels. A SECTION_END marker always closes
the last opened section; SECTION_START and SECTION_END items must be balanced
in a valid message.

### Key/Values ###

Key/Value pair elements may appear in the implicit root section or any explicit
sub-section at any level. Key names must be unique in the current section, use
lists to define multiple values for a key. Key/values may not appear in lists,
use a sub-section instead.

### Lists ###

Lists may appear at the same locations as Key/Values, and may not be nested.
Only a single list may be opened at the same time, and all lists must be closed
in valid messages. After opening a list, only list items may appear before the
list closing element. Empty lists are allowed, list items may appear within
lists only.

### Encoding example ###

Consider the following structure using pseudo-markup for this example:

	key1 = value1
	section1 = {
		sub-section = {
			key2 = value2
		}
		list1 = [ item1, item2 ]
	}

The example above reprensents a valid tree structure, that gets encoded as
the following C array:

	char msg[] = {
		/* key1 = value1 */
		2, 4,'k','e','y','1', 0,6,'v','a','l','u','e','1',
		/* section1 */
		0, 8,'s','e','c','t','i','o','n','1',
		/* sub-section */
		0, 11,'s','u','b','-','s','e','c','t','i','o','n',
		/* key2 = value2 */
		2, 4,'k','e','y','2', 0,6,'v','a','l','u','e','2',
		/* sub-section end */
		1,
		/* list1 */
		3, 5, 'l','i','s','t','1',
		/* item1 */
		4, 0,5,'i','t','e','m','1',
		/* item2 */
		4, 0,5,'i','t','e','m','2',
		/* list1 end */
		5,
		/* section1 end */
		1,
	};

# libvici C client library #

libvici is the reference implementation of a C client library implementing
the vici protocol. It builds upon libstrongswan, but provides a stable API
to implement client applications in the C programming language. libvici uses
the libstrongswan thread pool to deliver event messages asynchronously.

More information about the libvici API is available in the libvici.h header
file.
