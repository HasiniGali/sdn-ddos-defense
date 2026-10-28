import csv
import json
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

RYU_API = "http://127.0.0.1:8080/stats"
SWITCHES = [1, 2, 3]
INTERVAL = 5

OUTPUT_FILE = Path(__file__).resolve().parent / "switch_traffic.csv"

FIELDS = [
    "timestamp",
    "switch_id",
    "flow_count",
    "packets",
    "bytes",
    "packet_rate",
    "byte_rate",
]


def fetch_stats(endpoint):
    url = f"{RYU_API}/{endpoint}"

    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"API request failed: {error}")
        return None


def main():
    previous = {}

    file_exists = OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0

    with OUTPUT_FILE.open("a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDS)

        if not file_exists:
            writer.writeheader()

        print(f"Saving traffic statistics to: {OUTPUT_FILE}")
        print("Press Ctrl+C to stop.")

        try:
            while True:
                timestamp = datetime.now().isoformat(timespec="seconds")

                for switch_id in SWITCHES:
                    stats = fetch_stats(f"flow/{switch_id}")

                    if stats is None:
                        continue

                    flows = stats.get(str(switch_id), [])

                    packets = sum(
                        flow.get("packet_count", 0)
                        for flow in flows
                    )
                    byte_count = sum(
                        flow.get("byte_count", 0)
                        for flow in flows
                    )

                    current = (packets, byte_count)
                    old = previous.get(switch_id)

                    if old is None:
                        packet_rate = 0.0
                        byte_rate = 0.0
                    else:
                        elapsed = INTERVAL
                        packet_rate = max(0, packets - old[0]) / elapsed
                        byte_rate = max(0, byte_count - old[1]) / elapsed

                    previous[switch_id] = current

                    row = {
                        "timestamp": timestamp,
                        "switch_id": switch_id,
                        "flow_count": len(flows),
                        "packets": packets,
                        "bytes": byte_count,
                        "packet_rate": round(packet_rate, 2),
                        "byte_rate": round(byte_rate, 2),
                    }

                    writer.writerow(row)
                    csvfile.flush()

                    print(
                        f"{timestamp} | s{switch_id} | "
                        f"flows={len(flows)} | packets={packets} | "
                        f"bytes={byte_count} | "
                        f"pps={packet_rate:.2f} | "
                        f"Bps={byte_rate:.2f}"
                    )

                time.sleep(INTERVAL)

        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
            print(f"CSV saved at: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
