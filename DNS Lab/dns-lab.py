import dns
import socket
import sys

s = input("Please enter a domain: ")
split_domain = s.split('.')

ip = input("Type 1 for IPv4 or 2 for IPv6: ")
if (ip == '2'):
    ip_chosen = 28
else :
    ip_chosen = 1
   
print(ip_chosen)


question = dns.DNSQuestion(
    qname=split_domain,
    qtype=ip_chosen,  # 28 for ipv6 1 foiov4
    qclass=1
)

header = dns.DNSHeader(
    ident=1000,  # You can pick any number you want for this!
    qr=0,  # Set QR to zero to represent a query
    opcode=0,
    aa=0,
    tc=0,
    rd=1,  # Request recursion
    ra=0,
    z=0,
    rcode=0,
    qdcount=1,  # We have one question!
    ancount=0,
    nscount=0,
    arcount=0
)

datagram = dns.DNSDatagram(
    header=header,
    questions=[question],
    answers=[]
)

datagram_bytes = dns.make_dns_datagram(datagram)
destination = ('127.0.0.53', 53)
connection = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
connection.sendto(datagram_bytes, destination)

init_result = connection.recvfrom(4096)[0]

print(init_result)

result = dns.read_dns_datagram(init_result)

if (ip_chosen == 1):
    for i in range(len((result.answers))):
        print(f"{result.answers[i].rdata[0]}.{result.answers[i].rdata[1]}.{result.answers[i].rdata[2]}.{result.answers[i].rdata[3]}")
else:
    for i in range(len((result.answers))):
        hexstring = result.answers[i].rdata.hex()
        hex_segments = [hexstring[i:i+4] for i in range(0, len(hexstring), 4)]
        for j in range(len(hex_segments)):
            print(hex_segments[j] + ":", end='')
        
        print(" ")
    
