#!/usr/bin/env python3
import json
from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR, conf

# --- Configuration ---
RECORDS_FILE = "/etc/dns_records.json"

def load_dns_records():
    """Loads DNS records from the JSON file."""
    with open(RECORDS_FILE, 'r') as f:
        return json.load(f)

def handle_dns_query(packet):
    """
    Handles incoming DNS queries and sends a response based on hardcoded records.
    """
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return

    if packet[DNS].opcode == 0 and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode('utf-8')
        qtype_code = packet[DNSQR].qtype
        print(f"[*] Received DNS query for: {qname} (Type: {qtype_code}) from {packet[IP].src}")

        dns_records = load_dns_records()
        
        # Craft the response packet's IP and UDP layers first
        # Scapy will use the correct source IP based on the routing table
        response_pkt = IP(dst=packet[IP].src) / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)

        if qname in dns_records:
            ip_address = dns_records[qname]
            
            dns_response = DNS(
                id=packet[DNS].id,
                qr=1, # 1 for response
                aa=1, # 1 for authoritative answer
                qd=packet[DNS].qd, # Copy the question section
                an=DNSRR(
                    rrname=qname,
                    ttl=600,
                    rdata=ip_address
                )
            )
            print(f"[+] Found record. Replying with IP: {ip_address}")
            send(response_pkt/dns_response, verbose=0)
        else:
            dns_response = DNS(
                id=packet[DNS].id,
                qr=1,
                aa=1,
                rcode=3, # 3 for NXDOMAIN
                qd=packet[DNS].qd
            )
            print(f"[-] No record found for {qname}. Responding with NXDOMAIN.")
            send(response_pkt/dns_response, verbose=0)

def main():
    """
    Starts the DNS server.
    """
    print(f"[*] Starting DNS server...")
    
    # BPF filter to capture only DNS queries on port 53.
    # We remove the IP filter to listen on all interfaces.
    bpf_filter = "udp port 53"
    
    print(f"[*] Sniffing for DNS queries with filter: '{bpf_filter}'")

    try:
        # Remove the 'iface' argument to let Scapy auto-detect the correct interface.
        # This is the main fix for the "No such device" error.
        sniff(filter=bpf_filter, prn=handle_dns_query, store=0)
    except PermissionError:
        print("\n[!] Error: Permission denied. Please run the script with root privileges (sudo).")
    except Exception as e:
        # This will catch the "No such device" error if auto-detection fails
        print(f"\n[!] An error occurred during sniffing: {e}")
        print("[!] Please check your network interface name and manually specify it with the 'iface' parameter if needed.")

if __name__ == "__main__":
    main()

