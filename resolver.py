import json
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
import socket
import time

with open("root_servers.json", 'r') as f:
    roots = json.load(f)


class IterativeDNSResolver:
    def __init__(self, root_servers, timeout=5):
        self.root_servers = root_servers
        self.timeout = timeout
        self.cache = {}

    def resolve(self, domain_name, qtype=dns.rdatatype.A):
        cache_key = (domain_name, qtype)
        if cache_key in self.cache:
            if time.time() - self.cache[cache_key][
                'timestamp'] < 300:
                return self.cache[cache_key]['answers']

        current_servers = []

        for server_info in self.root_servers.values():
            if 'ipv4' in server_info:
                current_servers.append(server_info['ipv4'])
            if 'ipv6' in server_info:
                current_servers.append(server_info['ipv6'])

        visited_servers = set()
        max_iterations = 15
        iteration = 0

        while current_servers and iteration < max_iterations:
            iteration += 1
            server = current_servers.pop(0)

            if server in visited_servers:
                continue
            visited_servers.add(server)

            try:
                response = self.send_query(domain_name, qtype, server)

                direct_answers = [rrset for rrset in response.answer if
                                  rrset.rdtype == qtype]
                if direct_answers:
                    self.cache[cache_key] = {
                        'answers': response.answer,
                        'timestamp': time.time()
                    }
                    return response.answer

                cname_rrset = None
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        cname_rrset = rrset
                        break

                if cname_rrset:
                    cname_target = str(cname_rrset[0].target)
                    cname_result = self.resolve(cname_target, qtype)
                    if cname_result:
                        result = response.answer + cname_result
                        self.cache[cache_key] = {
                            'answers': result,
                            'timestamp': time.time()
                        }
                        return result

                next_servers = self.extract_next_servers(response)
                if next_servers:
                    current_servers = next_servers + current_servers

            except (dns.exception.Timeout, socket.timeout) as e:
                print(f"Timeout querying {server}: {e}")
                continue
            except Exception as e:
                print(f"Error querying {server}: {e}")
                continue

        print(
            f"Resolution failed for {domain_name} after {iteration} iterations")
        return None

    def send_query(self, domain_name, qtype, server):
        request = dns.message.make_query(domain_name, qtype)
        response = dns.query.udp(request, server, timeout=self.timeout)
        return response

    def extract_next_servers(self, response):
        next_servers = []

        if response.additional:
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    for item in rrset:
                        next_servers.append(item.address)
                elif rrset.rdtype == dns.rdatatype.AAAA:
                    for item in rrset:
                        next_servers.append(item.address)

        if not next_servers and response.authority:
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    for ns_server in rrset:
                        ns_name = str(ns_server.target)
                        print(f"Resolving NS server: {ns_name}")
                        a_records = self.resolve_ns_server(ns_name)
                        if a_records:
                            next_servers.extend(a_records)

        return next_servers

    def resolve_ns_server(self, ns_domain):
        try:
            addrinfo = socket.getaddrinfo(ns_domain, None)
            addresses = []
            for family, type, proto, canonname, sockaddr in addrinfo:
                if family in (socket.AF_INET, socket.AF_INET6):
                    addresses.append(sockaddr[0])
            return addresses
        except Exception as e:
            print(f"Failed to resolve NS server {ns_domain}: {e}")
            return None
