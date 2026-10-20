import csv
import json
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Ryu REST API
RYU_API = "http://127.0.0.1:8080/stats"

# Switches in our Mininet topology
SWITCHES = [1, 2, 3]

# Collection interval in seconds
WINDOW_SECONDS = 5

# Output CSV
OUTPUT_FILE = Path(__file__).resolve().parent / "traffic_features.csv"

FIELDS = [
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


def fetch_flow_stats(switch_id):
    """Fetch flow statistics from the Ryu REST API."""
    url = f"{RYU_API}/flow/{switch_id}"

    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return json.loads(response.read().decode())

    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Could not fetch switch {switch_id}: {error}")
        return None


def main():
    print("SDN traffic feature collector")
    print(f"Output file: {OUTPUT_FILE}")
    print("Collection interval: 5 seconds")
    print("Press Ctrl+C to stop.\n")

    file_exists = OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0

    with OUTPUT_FILE.open("a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDS)

        if not file_exists:
            writer.writeheader()

        try:
            while True:
                window_start = datetime.now().isoformat(timespec="seconds")

                for switch_id in SWITCHES:
                    stats = fetch_flow_stats(switch_id)

                    if stats is None:
                        continue

                    flows = stats.get(str(switch_id), [])

                    # These are switch-level aggregates.
                    packets = sum(
                        flow.get("packet_count", 0)
                        for flow in flows
                    )

                    byte_count = sum(
                        flow.get("byte_count", 0)
                        for flow in flows
                    )

                    flow_count = len(flows)

                    # This is a preliminary switch-level record.
                    # Source IP, destination count and protocol cannot
                    # be inferred reliably from MAC-only forwarding flows.
                    row = {
                        "src_ip": "UNKNOWN",
                        "window_start": window_start,
                        "pkts": packets,
                        "bytes": byte_count,
                        "pkt_rate": 0,
                        "byte_rate": 0,
                        "avg_pkt_size": (
                            round(byte_count / packets, 2)
                            if packets > 0 else 0
                        ),
                        "n_flows": flow_count,
                        "n_dst": 0,
                        "proto": "UNKNOWN",
                        "label": "",
                    }

                    writer.writerow(row)
                    csvfile.flush()

                    print(
                        f"s{switch_id} | "
                        f"packets={packets} | "
                        f"bytes={byte_count} | "
                        f"flows={flow_count}"
                    )

                print("-" * 50)
                time.sleep(WINDOW_SECONDS)

        except KeyboardInterrupt:
            print("\nCollection stopped.")
            print(f"Dataset saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
