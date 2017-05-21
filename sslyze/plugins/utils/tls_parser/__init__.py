import struct
from enum import Enum
from typing import Tuple


class NotEnoughData(ValueError):
    pass


class UnknownTypeByte(ValueError):
    pass


class UnknownTlsVersionByte(ValueError):
    pass


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
    def __init__(self, record_type, tls_version, record_length):
        # type: (TlsRecordTypeByte, TlsVersionEnum, int) -> None
        self.type = record_type
        self.tls_version = tls_version
        self.length = record_length

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsRecordHeader, int]
        if len(raw_bytes) < 5:
            raise NotEnoughData()

        record_type = TlsRecordTypeByte(struct.unpack('B', raw_bytes[0])[0])
        tls_version = TlsRecordTlsVersionBytes(raw_bytes[1:3])
        record_length = struct.unpack('!H', raw_bytes[3:5])[0]
        return TlsRecordHeader(record_type, tls_version, record_length), 5

    def to_bytes(self):
        bytes = b''
        # TLS Record type - 1 byte
        bytes += struct.pack('B', self.type.value)
        # TLS version - 2 bytes
        bytes += TlsRecordTlsVersionBytes[self.tls_version.name].value
        # Length - 2 bytes
        bytes += struct.pack('!H', self.length)
        return bytes


class TlsRecord(object):
    def __init__(self, record_header, subprotocol_message):
        # type: (TlsRecordHeader, TlsSubprotocolMessage) -> None
        self.header = record_header
        self.subprotocol_message = subprotocol_message

    @classmethod
    def from_bytes(cls, raw_bytes):
        record_header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)

        # Try to parse the record
        if record_header.type == TlsRecordTypeByte.HANDSHAKE:
            return TlsHandshakeRecord.from_bytes(raw_bytes)
        elif record_header.type in TlsRecordTypeByte:
            # Valid record type but we don't have the code to parse it right now
            record_data = raw_bytes[len_consumed:record_header.length]
            message = TlsSubprotocolMessage(record_data)
            return TlsRecord(record_header, message), len_consumed + record_header.length
        else:
            # Unknown type
            raise UnknownTypeByte()

    def to_bytes(self):
        bytes = b''
        bytes += self.header.to_bytes()
        bytes += self.subprotocol_message.to_bytes()
        return bytes


class TlsSubprotocolMessage(object):
    # Handshake, Alert, etc.
    # Unparsed message
    def __init__(self, message_data):
        # type: (bytes) -> None
        self.message_data = message_data

    def to_bytes(self):
        return self.message_data

    @property
    def size(self):
        return len(self.to_bytes())


class TlsAlertSeverityByte(Enum):
    WARNING = 0x01
    FATAL = 0x02


class TlsAlertMessage(TlsSubprotocolMessage):

    def __init__(self, alert_severity, alert_description):
        # type: (TlsAlertSeverityByte, int) -> None
        self.alert_severity = alert_severity
        # Right now the description is just stored as an int instead of a TlsAlertDescriptionByte
        self.alert_description = alert_description

    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsAlertMessage, int]
        if len(raw_bytes) < 2:
            raise NotEnoughData()

        alert_severity = TlsAlertSeverityByte(struct.unpack('B', raw_bytes[0])[0])
        alert_description = TlsAlertSeverityByte(struct.unpack('B', raw_bytes[1])[0])
        return TlsAlertMessage(alert_severity, alert_description), 2


class TlsAlertRecord(TlsRecord):
    def __init__(self, record_header, alert_message):
        # type: (TlsRecordHeader, TlsHandshakeMessage) -> None
        super(TlsAlertRecord, self).__init__(record_header, alert_message)

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsAlertRecord, int]
        header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)
        remaining_bytes = raw_bytes[len_consumed::]

        if header.type != TlsRecordTypeByte.ALERT:
            raise UnknownTypeByte()

        message, len_consumed_for_message = TlsAlertMessage.from_bytes(remaining_bytes)
        return TlsAlertRecord(header, message), len_consumed + len_consumed_for_message

    def to_bytes(self):
        raise NotImplementedError()


class TlsHandshakeMessage(TlsSubprotocolMessage):

    def __init__(self, handshake_type, handshake_data):
        # type: (TlsHandshakeTypeByte, bytes) -> None
        self.handshake_type = handshake_type
        self.handshake_data = handshake_data

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeMessage, int]
        if len(raw_bytes) < 4:
            raise NotEnoughData()

        handshake_type = TlsHandshakeTypeByte(struct.unpack('B', raw_bytes[0])[0])
        message_length = struct.unpack('!I', b'\x00' + raw_bytes[1:4])[0]
        message = raw_bytes[4:message_length + 1]
        return TlsHandshakeMessage(handshake_type, message), 4 + message_length

    def to_bytes(self):
        # type: () -> bytes
        bytes = b''
        # TLS Handshake type - 1 byte
        bytes += struct.pack('B', self.handshake_type.value)
        # TLS Handshake length - 3 bytes
        bytes += struct.pack('!I', len(self.handshake_data))[1:4]  # We only keep the first 3 out of 4 bytes
        # TLS Handshake message
        bytes += self.handshake_data
        return bytes


class TlsHandshakeRecord(TlsRecord):

    def __init__(self, record_header, handshake_message):
        # type: (TlsRecordHeader, TlsHandshakeMessage) -> None
        super(TlsHandshakeRecord, self).__init__(record_header, handshake_message)

    @classmethod
    def from_parameters(cls, tls_version, handshake_type, handshake_data):
        handshake_message = TlsHandshakeMessage(handshake_type, handshake_data)
        record_header = TlsRecordHeader(TlsRecordTypeByte.HANDSHAKE, tls_version, handshake_message.size)
        return TlsHandshakeRecord(record_header, handshake_message)

    @classmethod
    def from_bytes(cls, raw_bytes):
        # type: (bytes) -> Tuple[TlsHandshakeRecord, int]
        header, len_consumed = TlsRecordHeader.from_bytes(raw_bytes)
        remaining_bytes = raw_bytes[len_consumed::]

        if header.type != TlsRecordTypeByte.HANDSHAKE:
            raise UnknownTypeByte()

        # Try to parse the handshake record
        message, len_consumed_for_message = TlsHandshakeMessage.from_bytes(remaining_bytes)
        handshake_type = TlsHandshakeTypeByte(struct.unpack('B', remaining_bytes[0])[0])
        if handshake_type == TlsHandshakeTypeByte.SERVER_DONE:
            return TlsServerHelloDoneRecord(header), len_consumed_for_message
        elif handshake_type in TlsHandshakeTypeByte:
            # Valid handshake type but we don't have the code to parse it right now
            return TlsHandshakeRecord(header, message), len_consumed + len_consumed_for_message
        else:
            raise UnknownTypeByte()


class TlsServerHelloDoneRecord(TlsHandshakeRecord):

    def __init__(self, record_header):
        # A ServerHelloDone does not carry any actual data
        super(TlsServerHelloDoneRecord, self).__init__(record_header,
                                                       TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_DONE, b''))

    @classmethod
    def from_parameters(cls, tls_version):
        record_header = TlsRecordHeader(TlsRecordTypeByte.SERVER_DONE, tls_version, 0)
        return TlsServerHelloDoneRecord(record_header)

    @classmethod
    def from_bytes(cls, raw_bytes):
        parsed_record, len_consumed = super(TlsServerHelloDoneRecord, cls).from_bytes(raw_bytes)

        if parsed_record.handshake_message.type != TlsRecordTypeByte.SERVER_DONE:
            raise UnknownTypeByte()

        return TlsServerHelloDoneRecord(parsed_record.record_header), len_consumed


class TlsHeartbeatMessage(TlsSubprotocolMessage):

    def __init__(self, hearbeat_type, heartbeat_data):
        # type: (TlsHeartbeatTypeByte, bytes) -> None
        self.type = hearbeat_type
        self.data = heartbeat_data

    @classmethod
    def from_bytes(cls, raw_bytes):
        raise NotImplementedError()

    def to_bytes(self):
        # type: () -> bytes
        bytes = b''
        # Heartbeat message type - 1 byte
        bytes += struct.pack('B', self.type.value)
        # Heartbeat message length - 2 bytes
        bytes += struct.pack('!H', len(self.data))
        # Heartbead message data
        bytes += self.data
        # Padding is not handled
        return bytes


class TlsHeartbeatRequestRecord(TlsRecord):
    """https://tools.ietf.org/html/rfc6520.
    struct {
      HeartbeatMessageType type;
      uint16 payload_length;
      opaque payload[HeartbeatMessage.payload_length];
      opaque padding[padding_length];
    } HeartbeatMessage;
    """

    def __init__(self, record_header, heartbeat_message):
        super(TlsHeartbeatRequestRecord, self).__init__(record_header, heartbeat_message)

    @classmethod
    def from_parameters(cls, tls_version, heartbeat_data):
        # type: (TlsVersionEnum, bytes) -> TlsHeartbeatRequest
        message = TlsHeartbeatMessage(TlsHeartbeatTypeByte.REQUEST, heartbeat_data)
        record_header = TlsRecordHeader(TlsRecordTypeByte.HEARTBEAT, tls_version, message.size)
        return TlsHeartbeatRequestRecord(record_header, message)

    @classmethod
    def from_bytes(cls, raw_bytes):
        raise NotImplementedError()
