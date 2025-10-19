import dns.message


class DNSParser:
    @staticmethod
    def parse_raw(raw_data):
        return dns.message.from_wire(raw_data)
