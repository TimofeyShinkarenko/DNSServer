import socket
import sys
import argparse
import dns.message
import dns.rdatatype


def main():
    parser = argparse.ArgumentParser(description='DNS Client')
    parser.add_argument('domain', help='Domain name to resolve')
    parser.add_argument('-t', '--type', default='A',
                        choices=['A', 'AAAA', 'CNAME', 'MX', 'NS'],
                        help='Query type (default: A)')
    parser.add_argument('-s', '--server', default='127.0.0.1',
                        help='DNS server address (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=53,
                        help='DNS server port (default: 53)')

    args = parser.parse_args()

    query_type_map = {
        'A': dns.rdatatype.A,
        'AAAA': dns.rdatatype.AAAA,
        'CNAME': dns.rdatatype.CNAME,
        'MX': dns.rdatatype.MX,
        'NS': dns.rdatatype.NS
    }

    query_type = query_type_map.get(args.type, dns.rdatatype.A)

    try:
        query = dns.message.make_query(args.domain, query_type)
        query_data = query.to_wire()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        sock.sendto(query_data, (args.server, args.port))
        response_data, _ = sock.recvfrom(512)

        response = dns.message.from_wire(response_data)

        if response.answer:
            print("\nAnswers:")
            for rrset in response.answer:
                for item in rrset:
                    print(
                        f"  {rrset.name} {rrset.ttl} {dns.rdataclass.to_text(rrset.rdclass)} {dns.rdatatype.to_text(rrset.rdtype)} {item}")

        if response.authority:
            print("\nAuthority:")
            for rrset in response.authority:
                for item in rrset:
                    print(
                        f"  {rrset.name} {rrset.ttl} {dns.rdataclass.to_text(rrset.rdclass)} {dns.rdatatype.to_text(rrset.rdtype)} {item}")

        if response.additional:
            print("\nAdditional:")
            for rrset in response.additional:
                for item in rrset:
                    print(
                        f"  {rrset.name} {rrset.ttl} {dns.rdataclass.to_text(rrset.rdclass)} {dns.rdatatype.to_text(rrset.rdtype)} {item}")

        sock.close()

    except socket.timeout:
        print("Error: Request timed out")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Error: Connection refused to {args.server}:{args.port}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
