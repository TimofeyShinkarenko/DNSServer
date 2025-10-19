import dns.message


class DNSPacket:
    def __init__(self):
        self.packet = dns.message.make_query()

    def append_question(self, qname: str, qtype: dns.rdatatype,
                        qclass: dns.rdataclass):
        question = dns.message.Question(qname, qtype, qclass)
        self.packet.question.append(question)

    def get_packet(self):
        return self.packet
