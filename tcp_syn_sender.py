import socket
import struct

from checksum3 import cs


def ethernet_header(source_mac, destination_mac, protocol_number='0800'):
    source_mac_bytes = bytes.fromhex(source_mac)
    destination_mac_bytes = bytes.fromhex(destination_mac)
    protocol_number_bytes = bytes.fromhex(protocol_number)

    return struct.pack('!6s6s2s', destination_mac_bytes, source_mac_bytes, protocol_number_bytes)


def ip_header(source_ip, destination_ip, ip_version_header_length='45', type_of_service='00', total_length='0028', identificaton='07c3',
              flags='4000', ttl='40', protocol='06'):
    ip_version_header_length_bytes = bytes.fromhex(ip_version_header_length)
    type_of_service_bytes = bytes.fromhex(type_of_service)
    total_length_bytes = bytes.fromhex(total_length)
    identificaton_bytes = bytes.fromhex(identificaton)
    flags_bytes = bytes.fromhex(flags)
    ttl_bytes = bytes.fromhex(ttl)
    protocol_bytes = bytes.fromhex(protocol)
    ip_checksum_bytes = bytes.fromhex('0000')
    source_ip = socket.inet_aton(source_ip)
    destination_ip = socket.inet_aton(destination_ip)

    calculating_checksum = struct.pack('!ss2s2s2s1s1s2s4s4s', ip_version_header_length_bytes, type_of_service_bytes,
                                       total_length_bytes, identificaton_bytes, flags_bytes, ttl_bytes, protocol_bytes,
                                       ip_checksum_bytes, source_ip, destination_ip)
    hex_header = calculating_checksum.hex()
    hex_header = ' '.join(hex_header[i:i+2]
                          for i in range(0, len(hex_header), 2))
    ip_checksum = cs(hex_header)
    ip_checksum_bytes = bytes.fromhex(ip_checksum)

    return struct.pack('!s1s2s2s2s1s1s2s4s4s', ip_version_header_length_bytes, type_of_service_bytes,
                       total_length_bytes, identificaton_bytes, flags_bytes, ttl_bytes, protocol_bytes,
                       ip_checksum_bytes, source_ip, destination_ip)


def tcp_header(source_port, destination_port, source_ip, destination_ip, tcp_length='0014',
               ip_protocol='06', reserved='0000', seq_number='174930d1', ack_number='00000000',
               header_length='5002', window_size='7210', urgent_pointer='0000'):

    source_port = bytes.fromhex(hex(int(source_port))[2:].zfill(4))
    destination_port = bytes.fromhex(hex(int(destination_port))[2:].zfill(4))
    seq_number_bytes = bytes.fromhex(seq_number)
    ack_number_bytes = bytes.fromhex(ack_number)
    header_length_bytes = bytes.fromhex(header_length)
    window_size_bytes = bytes.fromhex(window_size)
    urgent_pointer_bytes = bytes.fromhex(urgent_pointer)
    tcp_checksum_bytes = bytes.fromhex('0000')

    source_ip = socket.inet_aton(source_ip)
    destination_ip = socket.inet_aton(destination_ip)
    tcp_length_bytes = bytes.fromhex(tcp_length)
    ip_protocol_bytes = bytes.fromhex(ip_protocol)
    reserved_bytes = bytes.fromhex(reserved)

    calculating_checksum = struct.pack('!4s4sss2s2s2s4s4s2s2s2s2s', source_ip, destination_ip, reserved_bytes, ip_protocol_bytes, tcp_length_bytes, source_port, destination_port, seq_number_bytes,
                                       ack_number_bytes, header_length_bytes, window_size_bytes, tcp_checksum_bytes,
                                       urgent_pointer_bytes)
    hex_header = calculating_checksum.hex()
    hex_header = ' '.join(hex_header[i:i+2]
                          for i in range(0, len(hex_header), 2))
    tcp_checksum = cs(hex_header)
    tcp_checksum_bytes = bytes.fromhex(tcp_checksum)

    return struct.pack('!2s2s4s4s2s2s2s2s', source_port, destination_port, seq_number_bytes,
                       ack_number_bytes, header_length_bytes, window_size_bytes, tcp_checksum_bytes, urgent_pointer_bytes)


if __name__ == '__main__':
    with open("info.txt", encoding='utf-8') as file:
        lines = file.readlines()
        server_ip_address = lines[0].strip()
        server_port_number = lines[1].strip()
        interface_ip_address = lines[2].strip()
        source_port = lines[3].strip()
        interface_name = lines[4].strip()
        interface_mac_address = lines[5].strip().replace(" ", "")
        gateway_mac_address = lines[6].strip().replace(" ", "")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((interface_name, 0))
    content = ethernet_header(interface_mac_address, gateway_mac_address) +\
        ip_header(interface_ip_address, server_ip_address) +\
        tcp_header(source_port, server_port_number,
                   interface_ip_address, server_ip_address)
    s.send(content)
    print(f'Sent {len(content)}-byte TCP SYN packet on {interface_name}')
