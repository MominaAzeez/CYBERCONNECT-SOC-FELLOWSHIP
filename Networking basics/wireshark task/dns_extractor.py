import pyshark
import sys


def extract_dns_queries(pcap_file):
    try:
        capture = pyshark.FileCapture(
            pcap_file,
            display_filter='dns.flags.response == 0'
        )

        seen = set()
        dns_server_ip = None
        results = []

        for packet in capture:
            try:
                if 'DNS' in packet:
                    domain = packet.dns.qry_name

                    if hasattr(packet, 'ip'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                    elif hasattr(packet, 'ipv6'):
                        src_ip = packet.ipv6.src
                        dst_ip = packet.ipv6.dst
                    else:
                        continue

                    if dns_server_ip is None:
                        dns_server_ip = dst_ip

                    key = (src_ip, domain)
                    if key not in seen:
                        seen.add(key)
                        results.append((src_ip, domain))

            except AttributeError:
                continue

        capture.close()

        print("PyShark DNS Query Extractor")
        print("=" * 40)
        print(f"DNS IP Address: {dns_server_ip}\n")
        print(f"{'Source IP':<20} {'Domain Name'}")
        print("-" * 50)
        for src_ip, domain in results:
            print(f"{src_ip:<20} {domain}")

    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dnsExtract.py <file.pcap or file.pcapng>")
        sys.exit(1)

    extract_dns_queries(sys.argv[1])
