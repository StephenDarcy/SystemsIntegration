import dns
import socket
import sys

# user passed in value s= "google.com"
# use s.split('.')

question = dns.DNSQuestion(
    qname=["tudublin", "ie"],
    qtype=1,  # 28 for ipv6
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
destination = ('HEIMDALL.ict.ad.dit.ie', 53)
connection = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
connection.sendto(datagram_bytes, destination)

result = connection.recvfrom(4096)[0]

print(result)

print(dns.read_dns_datagram(result))


# print(f`{answer.rdata[0]}.{answer.rdata[1]}.{answer.rdata[2]}.{answer.rdata[3]}`)
