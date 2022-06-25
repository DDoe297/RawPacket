import socket
import struct
from dataclasses import dataclass
from typing import Final, List, Tuple

ETHERNET_IPV4: Final = 0x0800
IPV4_TCP: Final = 0x6


@dataclass
class EthernetFrame:
    destination: bytes
    source: bytes
    protocol_number: int
    payload: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[bytes] = struct.unpack("!6s6s2s", data[:14])
        self.destination: bytes = header[0]
        self.source: bytes = header[1]
        self.protocol_number: int = int.from_bytes(header[2], 'big')
        self.payload: bytes = data[14:]


@dataclass
class IPDatagram:
    version: int
    header_length: int
    type_of_service: bytes
    total_length: int
    fragmentation_data: bytes
    ttl: int
    protocol: int
    header_checksum: bytes
    source_address: bytes
    destination_address: bytes
    payload: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[bytes | int] = struct.unpack("!BsH4sBB2s4s4s", data[:20])
        self.version = header[0] >> 4
        self.header_length = header[0] & (0x0F)*4
        self.type_of_service = header[1]
        self.total_length = header[2]
        self.fragmentation_data = header[3]
        self.ttl = header[4]
        self.protocol = header[5]
        self.header_checksum = header[6]
        self.source_address = header[7]
        self.destination_address = header[8]
        self.payload = data[20:]


@dataclass
class TCPFlags:
    NS: bool
    CWR: bool
    ECE: bool
    URG: bool
    ACK: bool
    PSH: bool
    RST: bool
    SYN: bool
    FIN: bool

    def __init__(self, flags: int) -> None:
        self.FIN = bool(flags & 1)
        self.SYN = bool((flags & 2) >> 1)
        self.RST = bool((flags & 4) >> 2)
        self.PSH = bool((flags & 8) >> 3)
        self.ACK = bool((flags & 16) >> 4)
        self.URG = bool((flags & 32) >> 5)
        self.ECE = bool((flags & 64) >> 6)
        self.CWR = bool((flags & 128) >> 7)
        self.NS = bool((flags & 256) >> 8)


@dataclass
class TCPSegment:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgement_number: int
    header_length: int
    flags: TCPFlags
    window_size: int
    tcp_checksum: bytes
    urgent_pointer: bytes
    payload: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[bytes | int] = struct.unpack("!HHiihh2s2s", data[:20])
        self.source_port = header[0]
        self.destination_port = header[1]
        self.sequence_number = header[2]
        self.acknowledgement_number = header[3]
        self.header_length = header[4] >> 12
        self.flags = TCPFlags(header[4] & (0x1FF))
        self.window_size = header[5]
        self.tcp_checksum = header[6]
        self.urgent_pointer = header[7]
        self.payload = data[20:]


def EthernetFrameHandler(data: bytes, seen_ports: List[Tuple[str,int]]):
    frame = EthernetFrame(data)
    if frame.protocol_number == ETHERNET_IPV4:
        datagram = IPDatagram(frame.payload)
        if datagram.protocol == IPV4_TCP:
            segment = TCPSegment(datagram.payload)
            if segment.flags.SYN and segment.flags.ACK:
                port = segment.source_port
                IP = socket.inet_ntoa(datagram.source_address)
                if (IP,port) not in seen_ports:
                    seen_ports.append((IP,port))
                    print(f'Port {port} is open on {IP}')


if __name__ == '__main__':
    interface = input('Which interface do you want to use?')
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((interface, 0))
    seen_ports = []
    while True:
        data = s.recv(1514)
        EthernetFrameHandler(data,seen_ports)
