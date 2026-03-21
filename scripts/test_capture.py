import sys
sys.path.insert(0, '.')
from src.ingestion.live_capture import LiveCaptureReader

reader = LiveCaptureReader(interface='Wi-Fi', bpf_filter='')
count = 0
print("Starting capture...")
for pkt in reader.start_capture():
    src = pkt.get("src_ip", "?")
    dst = pkt.get("dst_ip", "?")
    proto = pkt.get("protocol", "?")
    tls = pkt.get("has_tls_layer", False)
    size = pkt.get("packet_size", 0)
    print(f"Packet: {src} -> {dst} | {proto} | TLS:{tls} | {size}b")
    count += 1
    if count >= 5:
        break
print(f"Done — got {count} packets")