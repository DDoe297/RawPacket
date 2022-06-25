import socket
from time import sleep

from tcp_syn_sender import ethernet_header, ip_header, tcp_header

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
    server_ip_address = input('What is the target IP address?')
    port_range = list(
        map(int, input('Which ports do you want to scan?').split("-")))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((interface_name, 0))
    data = ethernet_header(interface_mac_address, gateway_mac_address) +\
        ip_header(interface_ip_address, server_ip_address)
    for port in range(port_range[0], port_range[1]+1):
        content = data +\
            tcp_header(source_port, port,
                       interface_ip_address, server_ip_address)
        length = s.send(content)
        print(f'Sent {length}-byte TCP SYN packet to port {port}')
        sleep(0.01)
