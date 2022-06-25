import socket

if __name__ == '__main__':
    server_ip_address = input('What is the target IP address?')
    port_range = list(
        map(int, input('Which ports do you want to scan?').split("-")))
    for port in range(port_range[0], port_range[1]+1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((server_ip_address, port)) == 0:
                print(f'Port {port} is open on {server_ip_address}')
