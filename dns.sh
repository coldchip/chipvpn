iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to 8.8.8.8:53

iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to 8.8.8.8:53

iptables -t nat -A POSTROUTING -j MASQUERADE
