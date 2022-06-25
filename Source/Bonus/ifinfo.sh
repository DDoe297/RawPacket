#/bin/bash
gateway_mac=$(arp -n | grep `route -n | awk '/UG/{print $2}'` | awk '{print $3}' | tr ':' ' ');
self_mac=$(ifconfig $3 | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' | tr ':' ' ';);
self_IP=$(ip -f inet addr show $3 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p');
printf "$1\n$2\n$self_IP\n$4\n$3\n$self_mac\n$gateway_mac\n">info.txt;