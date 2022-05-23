import socket
content = bytes.fromhex(input('What is your packet content?'))
interface = input('Which interface do you want to use?')
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((interface, 0))
s.send(content)
print(f'Sent {len(content)}-byte packet on {interface}')
