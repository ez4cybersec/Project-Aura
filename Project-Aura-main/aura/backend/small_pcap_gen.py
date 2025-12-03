from scapy.all import Ether, IP, TCP, Raw, wrpcap

# Create a small PCAP with 5 packets
packets = []
for i in range(5):
    pkt = Ether()/IP(dst="192.168.1.5")/TCP(dport=80)/Raw(load=f"GET /login?user=admin' OR 1=1 -- HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(pkt)

output_path = "small_test.pcap"
wrpcap(output_path, packets)
print(f"Created {output_path}")
