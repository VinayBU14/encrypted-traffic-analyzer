# scripts/inspect_packets.py

import sys
import os
sys.path.insert(0, os.path.abspath("."))

from src.ingestion.pcap_reader import PCAPReader

reader = PCAPReader("data/raw/pcap/test_sample.pcap")

for i, pkt in enumerate(reader.read_packets()):
    if i >= 5:  # print first 5 packets only
        break
    
    print(f"\n{'='*60}")
    print(f"PACKET {i+1}")
    print(f"{'='*60}")
    print(f"  timestamp    : {pkt['timestamp']}")
    print(f"  src_ip       : {pkt['src_ip']}")
    print(f"  dst_ip       : {pkt['dst_ip']}")
    print(f"  src_port     : {pkt['src_port']}")
    print(f"  dst_port     : {pkt['dst_port']}")
    print(f"  protocol     : {pkt['protocol']}")
    print(f"  packet_size  : {pkt['packet_size']} bytes")
    print(f"  payload_size : {pkt['payload_size']} bytes")
    print(f"  has_tls      : {pkt['has_tls_layer']}")
    print(f"  tcp_flags    :")
    for flag, val in pkt['tcp_flags'].items():
        if val:  # only print flags that are SET
            print(f"    {flag}: {val}")
    
    # bonus — peek into raw packet if TLS
    if pkt['has_tls_layer']:
        raw = pkt['raw_packet']
        try:
            print(f"  tls_version  : {raw.tls.record_version}")
            print(f"  tls_type     : {raw.tls.record_content_type}")
        except:
            pass