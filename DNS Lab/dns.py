import struct


from dataclasses import dataclass


def read_labels(b, i):
    output = []
    length = struct.unpack('!B', b[i:i+1])[0]
    working = []
    while length > 0:
        i += 1
        
        # Deal with compressed labels
        if length & 0xC0 != 0:
            offset = (length << 8) + b[i]
            output, _ = read_labels(b, offset & 0x3F)
            return output, i + 1
        
        for j in range(length):
            item = b[i + j]
            working.append(item)
        output.append(bytes(working).decode('utf-8'))
        working = []
        i += length
        length = struct.unpack('!B', b[i:i+1])[0]
    
    return output, i + 1


def make_labels(labels):
    output = []
    for label in labels:
        label = label.encode('utf-8')
        output.append(len(label))
        for char in label:
            output.append(char)
    output.append(0)
    return bytes(output)


@dataclass
class DNSQuestion:
    qname: list
    qtype: int
    qclass: int


def read_question(question: bytes, index: int) -> tuple:
    qname, index = read_labels(question, index)
    qtype = struct.unpack('!H', question[index:index+2])[0]
    qclass = struct.unpack('!H', question[index+2:index+4])[0]
    return DNSQuestion(qname, qtype, qclass), index + 4


def make_question(question: DNSQuestion) -> bytes:
    mask = 2 ** 16 - 1
    output = make_labels(question.qname)
    output += struct.pack('!H', question.qtype & mask)
    output += struct.pack('!H', question.qclass & mask)
    return output


@dataclass
class DNSAnswer:
    name: list
    dns_type: int
    dns_class: int
    ttl: int
    rdlength: int
    rdata: bytes


def read_answer(answer: bytes, index: int) -> tuple:
    name, index = read_labels(answer, index)
    dns_type = struct.unpack('!H', answer[index:index+2])[0]
    dns_class = struct.unpack('!H', answer[index+2:index+4])[0]
    ttl = struct.unpack('!I', answer[index+4:index+8])[0]
    rdlength = struct.unpack('!H', answer[index+8:index+10])[0]
    rdata = answer[index+10:index+10+rdlength]
    return DNSAnswer(
        name = name,
        dns_type = dns_type,
        dns_class = dns_class,
        ttl = ttl,
        rdlength = rdlength,
        rdata = rdata
    ), index + 10 + rdlength


def make_answer(answer: DNSAnswer) -> bytes:
    mask = 2 ** 16 - 1
    output = make_labels(answer.name)
    output += struct.pack('!H', answer.dns_type)
    output += struct.pack('!H', answer.dns_class)
    output += struct.pack('!H', answer.ttl)
    output += struct.pack('!H', answer.rdlength)
    output += answer.rdata
    return output


@dataclass
class DNSHeader:
    ident: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


def make_header(header: DNSHeader) -> bytes:
    output = b''
    output += struct.pack('!H', header.ident)
    flags = (header.qr & 1) << 15
    flags += (header.opcode & 15) << 10
    flags += (header.tc & 1) << 9
    flags += (header.rd & 1) << 8
    flags += (header.ra & 1) << 7
    flags += (header.z & 7) << 4
    flags += header.rcode & 15
    output += struct.pack('!H', flags)
    output += struct.pack('!H', header.qdcount)
    output += struct.pack('!H', header.ancount)
    output += struct.pack('!H', header.nscount)
    output += struct.pack('!H', header.arcount)
    return output


def read_header(header: bytes) -> DNSHeader:
    ident = struct.unpack('!H', header[:2])[0]
    flags = struct.unpack('!H', header[2:4])[0]
    rcode = flags & 15
    flags >>= 4
    z = flags & 7
    flags >>= 3
    ra = flags & 1
    flags >>= 1
    rd = flags & 1
    flags >>= 1
    tc = flags & 1
    flags >>= 1
    aa = flags & 1
    flags >>= 1
    opcode = flags & 15
    flags >>= 4
    qr = flags & 1
    qdcount = struct.unpack('!H', header[4:6])[0]
    ancount = struct.unpack('!H', header[6:8])[0]
    nscount = struct.unpack('!H', header[8:10])[0]
    arcount = struct.unpack('!H', header[10:12])[0]
    return DNSHeader(
        ident = ident,
        qr = qr,
        opcode = opcode,
        aa = aa,
        tc = tc,
        rd = rd,
        ra = ra,
        z = z,
        rcode = rcode,
        qdcount = qdcount,
        ancount = ancount,
        nscount = nscount,
        arcount = arcount
    )


@dataclass
class DNSDatagram:
    header: DNSHeader
    questions: list
    answers: list


def read_dns_datagram(data: bytes) -> DNSDatagram:
    header = read_header(data)
    questions = []
    answers = []
    index = 12
    for i in range(header.qdcount):
        question, index = read_question(data, index)
        questions.append(question)
    for i in range(header.ancount):
        answer, index = read_answer(data, index)
        answers.append(answer)
    return DNSDatagram(
        header = header,
        questions = questions,
        answers = answers
    )


def make_dns_datagram(data: DNSDatagram) -> bytes:
    output = make_header(data.header)
    assert len(data.questions) == data.header.qdcount
    assert len(data.answers) == data.header.ancount
    for question in data.questions:
        output += make_question(question)
    for answer in data.answers:
        output += make_answer(answer)
    return output
