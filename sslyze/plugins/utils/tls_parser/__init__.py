import struct
from enum import Enum


class TlsVersionEnum(Enum):
    SSLV3 = 0
    TLSV1 = 1
    TLSV1_1 = 2
    TLSV1_2 = 3


class TlsRecordTlsVersionBytes(Enum):
    SSLV3 = b'\x03\x00'
    TLSV1 = b'\x03\x01'
    TLSV1_1 = b'\x03\x02'
    TLSV1_2 = b'\x03\x03'


class TlsRecordTypeByte(Enum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18


class TlsHandshakeTypeByte(Enum):
   HELLO_REQUEST = 0x00
   CLIENT_HELLO = 0x01
   SERVER_HELLO = 0x02
   CERTIFICATE = 0x0b
   SERVER_KEY_EXCHANGE = 0x0c
   CERTIFICATE_REQUEST = 0x0d
   SERVER_DONE = 0x0e
   CERTIFICATE_VERIFY = 0x0f
   CLIENT_KEY_EXCHANGE = 0x10
   FINISHED = 0x14


class TlsHeartbeatTypeByte(Enum):
   REQUEST = 0x01
   RESPONSE = 0x02


class TlsRecordHeader(object):
    def __init__(self, tls_version, record_type, record_length):
        # type: (TlsVersionEnum, TlsRecordTypeByte, int) -> None
        self._tls_version = tls_version
        self._record_type = record_type
        self._record_length = record_length

        self._bytes = b''
        self._bytes += struct.pack('B', record_type.value)
        self._bytes += TlsRecordTlsVersionBytes[tls_version.name].value
        self._bytes += struct.pack('>H', self._record_length)

    @classmethod
    def from_bytes(cls, raw_bytes):
        raise NotImplementedError()

    def to_bytes(self):
        return self._bytes


class TlsHeartbeatRequest(object):
    """https://tools.ietf.org/html/rfc6520.
    struct {
      HeartbeatMessageType type;
      uint16 payload_length;
      opaque payload[HeartbeatMessage.payload_length];
      opaque padding[padding_length];
    } HeartbeatMessage;
    """

    def __init__(self, tls_version, heartbeat_payload):
        # type: (TlsVersionEnum, bytes) -> None
        self._heartbeat_payload = heartbeat_payload

        self._bytes = b''
        self._bytes += struct.pack('B', TlsHeartbeatTypeByte.REQUEST.value)
        self._bytes += struct.pack('>H', len(heartbeat_payload))
        self._bytes += heartbeat_payload
        # Padding is not handled

        self._header = TlsRecordHeader(tls_version, TlsRecordTypeByte.HEARTBEAT, len(self._bytes))

    @classmethod
    def from_bytes(cls, raw_bytes):
        raise NotImplementedError()

    def to_bytes(self):
        # type: () -> bytes
        return self._header.to_bytes() + self._bytes

