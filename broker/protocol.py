#!/usr/bin/python
import construct

# Control message for our protocol; first few bits are special as we have to
# maintain compatibility with LTPv3 in the kernel (first bit must be 1); also
# the packet must be at least 12 bytes in length, otherwise some firewalls
# may filter it when used over port 53
ControlMessage = construct.Struct(
  # Ensure that the first bit is 1 (L2TP control packet)
  "magic1" / construct.Const(0x80, construct.Int8ub),
  # Reduce conflict matching to other protocols as we run on port 53
  "magic2" / construct.Const(0x73A7, construct.Int16ub),
  # Protocol version to allow future upgrades
  "version" / construct.Int8ub,
  # Message type
  "type" / construct.Int8ub,
  # Message data (with length prefix)
  "data_size" / construct.Int8ub,
  "data" / construct.Bytes(construct.this.data_size),
  # Pad the message so it is at least 12 bytes long
  construct.Optional(construct.Padding(lambda ctx: max(0, 6 - len(ctx["data"])))),
)

# Unreliable messages (0x00 - 0x7F)
CONTROL_TYPE_COOKIE    = 0x01
CONTROL_TYPE_PREPARE   = 0x02
CONTROL_TYPE_ERROR     = 0x03
CONTROL_TYPE_TUNNEL    = 0x04
CONTROL_TYPE_KEEPALIVE = 0x05
CONTROL_TYPE_PMTUD     = 0x06
CONTROL_TYPE_PMTUD_ACK = 0x07
CONTROL_TYPE_REL_ACK   = 0x08
CONTROL_TYPE_PMTU_NTFY = 0x09
CONTROL_TYPE_USAGE     = 0x0A

# Error Reason Byte
# e.g. a client shutdown. it sends 0x11 to the server which answer with 0x00 (other request)
# left nibble is direction
ERROR_REASON_FROM_SERVER = 0x00
ERROR_REASON_FROM_CLIENT = 0x10
# right nibble is error code
ERROR_REASON_OTHER_REQUEST  = 0x01 # other site requested
ERROR_REASON_SHUTDOWN       = 0x02 # shutdown
ERROR_REASON_TIMEOUT        = 0x03
ERROR_REASON_FAILURE        = 0x04 # e.q. on malloc() failure
ERROR_REASON_UNDEFINED      = 0x05

# Reliable messages (0x80 - 0xFF)
MASK_CONTROL_TYPE_RELIABLE = 0x80
CONTROL_TYPE_LIMIT     = 0x80

# Prepare message
PrepareMessage = construct.Struct(
  "cookie" / construct.Bytes(8),
  "uuid" / construct.PascalString(construct.VarInt, 'utf8'),
  "tunnel_id" / construct.Optional(construct.Int16ub),
)

# Limit message
LimitMessage = construct.Struct(
  # Limit type
  "type" / construct.Int8ub,
  # Limit configuration
  "bandwidth" / construct.Int32ub,
)

# Error message
ErrorMessage = construct.Struct(
  # reason type
  "reason" / construct.Int8ub,
)

LIMIT_TYPE_BANDWIDTH_DOWN = 0x01

# Overhead of IP and UDP headers for measuring PMTU
IPV4_HDR_OVERHEAD = 28

# L2TP data header overhead for calculating tunnel MTU; takes
# the following headers into account:
#
#   20 bytes (IP header)
#    8 bytes (UDP header)
#    4 bytes (L2TPv3 Session ID)
#    4 bytes (L2TPv3 Cookie)
#    4 bytes (L2TPv3 Pseudowire CE)
#   14 bytes (Ethernet)
#
L2TP_TUN_OVERHEAD = 54

# Control header overhead for a zero-length payload
L2TP_CONTROL_SIZE = 6

# Ioctls
SIOCSIFMTU = 0x8922

# Socket options
IP_MTU_DISCOVER = 10
IP_PMTUDISC_PROBE = 3
SO_BINDTODEVICE = 25

# L2TP generic netlink
L2TP_GENL_NAME = b"l2tp"
L2TP_GENL_VERSION = 0x1

# L2TP netlink commands
L2TP_CMD_TUNNEL_CREATE = 1
L2TP_CMD_TUNNEL_DELETE = 2
L2TP_CMD_TUNNEL_GET = 4
L2TP_CMD_SESSION_CREATE = 5
L2TP_CMD_SESSION_DELETE = 6
L2TP_CMD_SESSION_MODIFY = 7
L2TP_CMD_SESSION_GET = 8

# L2TP netlink command attributes
L2TP_ATTR_NONE = 0
L2TP_ATTR_PW_TYPE = 1
L2TP_ATTR_ENCAP_TYPE = 2
L2TP_ATTR_PROTO_VERSION = 7
L2TP_ATTR_IFNAME = 8
L2TP_ATTR_CONN_ID = 9
L2TP_ATTR_PEER_CONN_ID = 10
L2TP_ATTR_SESSION_ID = 11
L2TP_ATTR_PEER_SESSION_ID = 12
L2TP_ATTR_FD = 23
L2TP_ATTR_MTU = 28

# L2TP encapsulation types
L2TP_ENCAPTYPE_UDP = 0

# L2TP pseudowire types
L2TP_PWTYPE_ETH = 0x0005
