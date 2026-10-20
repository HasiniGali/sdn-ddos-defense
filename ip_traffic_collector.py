import csv
import time
import threading
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

INTERFACE = "s1-eth3"
WINDOW_SECONDS = 5
OUTPUT_FILE = "ip_traffic.csv"

lock = threading.Lock()
traffic = defaultdict(
    lambda: {
        "pkts": 0,
        "bytes": 0,
        "destinations": set(),
        "protocols": set(),
        "flows": set(),
    }
)


def packet_callback(packet):
    if IP not in packet:
        return

    ip = packet[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    protocol = ip.proto
    packet_size = len(packet)

    if TCP in packet:
        proto_name = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        proto_name = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        proto_name = "ICMP"
        src_port = dst_port = 0
    else:
        proto_name = str(protocol)
        src_port = dst_port = 0

    window_start = int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS
    key = (src_ip, window_start)

    with lock:
        record = traffic[key]
        record["pkts"] += 1
        record["bytes"] += packet_size
        record["destinations"].add(dst_ip)
        record["protocols"].add(proto_name)
        record["flows"].add(
            (src_ip, dst_ip, proto_name, src_port, dst_port)
        )


def writer():
    fieldnames = [
        "src_ip",
        "window_start",
        "pkts",
        "bytes",
        "pkt_rate",
        "byte_rate",
        "avg_pkt_size",
        "n_flows",
        "n_dst",
        "proto",
        "label",
    ]

    with open(OUTPUT_FILE, "w", newline="") as file:
        csv.DictWriter(file, fieldnames=fieldnames).writeheader()

    while True:
        time.sleep(WINDOW_SECONDS)

        cutoff = int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS
        completed = []

        with lock:
            for key in list(traffic.keys()):
                if key[1] < cutoff:
                    completed.append((key, traffic.pop(key)))

        if not completed:
            continue

        with open(OUTPUT_FILE, "a", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            for (src_ip, window_start), record in completed:
                pkts = record["pkts"]
                byte_count = record["bytes"]

                writer.writerow({
                    "src_ip": src_ip,
                    "window_start": datetime.fromtimestamp(
                        window_start
                    ).isoformat(),
                    "pkts": pkts,
                    "bytes": byte_count,
                    "pkt_rate": round(pkts / WINDOW_SECONDS, 3),
                    "byte_rate": round(byte_count / WINDOW_SECONDS, 3),
                    "avg_pkt_size": round(byte_count / pkts, 2),
                    "n_flows": len(record["flows"]),
                    "n_dst": len(record["destinations"]),
                    "proto": "|".join(sorted(record["protocols"])),
                    "label": "",
                })


if __name__ == "__main__":
    print(f"Capturing IPv4 traffic on {INTERFACE}")
    print(f"Writing traffic features to {OUTPUT_FILE}")
    print("Press Ctrl+C to stop.")

    threading.Thread(target=writer, daemon=True).start()

    try:
        sniff(
            iface=INTERFACE,
            filter="ip",
            prn=packet_callback,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nStopping collector...")
