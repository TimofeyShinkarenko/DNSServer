import json
import asyncio
import dns.message
import dns.rdatatype
from resolver import IterativeDNSResolver

with open("root_servers.json", 'r') as f:
    roots = json.load(f)


class UDPDNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver):
        self.resolver = resolver

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            query = dns.message.from_wire(data)
            response_message = dns.message.make_response(query)

            for question in query.question:
                answers = self.resolver.resolve(str(question.name),
                                                question.rdtype)

                if answers:
                    for answer in answers:
                        response_message.answer.append(answer)
                else:
                    response_message.set_rcode(dns.rcode.NXDOMAIN)

            response_data = response_message.to_wire()
            self.transport.sendto(response_data, addr)

        except Exception as e:
            try:
                error_response = dns.message.make_response(query)
                error_response.set_rcode(dns.rcode.SERVFAIL)
                self.transport.sendto(error_response.to_wire(), addr)
            except:
                pass


class DNSServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.resolver = IterativeDNSResolver(roots)

    async def start_server(self):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPDNSProtocol(self.resolver),
            local_addr=(self.host, self.port)
        )

        try:
            await asyncio.sleep(float('inf'))
        finally:
            transport.close()


if __name__ == "__main__":
    server = DNSServer("192.168.0.105", 1234)
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        print("Server stopped")
