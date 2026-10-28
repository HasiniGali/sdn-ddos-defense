"""Command builders for benign and attack traffic inside Mininet hosts.

Attack commands are only ever built for targets inside the emulated network;
anything else raises, so a typo cannot aim hping3 at a real address.
"""
import ipaddress

EMULATED_NET = ipaddress.ip_network("10.0.0.0/24")

# Attack shapes: hping3 mode flags and payload bytes.
ATTACKS = {
    "syn": ["-S", "-p", "80"],
    "udp": ["--udp", "-p", "9", "-d", "512"],
    "icmp": ["--icmp", "-d", "512"],
}

# Nominal packets/s per attacker for each rate level.
RATES = {"low": 50, "medium": 500, "high": 5000}

# Mean think time (s) between HTTP requests per benign client.
BENIGN_LOAD = {"low": 2.0, "medium": 0.5, "high": 0.1}
ATTACKER_THINK_S = 2.0   # attackers also browse lightly, outside and during attacks

HTTP_FILES = {"1k.bin": 1_000, "10k.bin": 10_000, "100k.bin": 100_000}


def assert_internal_target(ip):
    if ipaddress.ip_address(ip) not in EMULATED_NET:
        raise ValueError(f"refusing to target {ip}: outside {EMULATED_NET}")


def hping3_cmd(kind, pps, target):
    assert_internal_target(target)
    interval_us = max(1, int(1e6 / pps))
    return ["hping3", "-q", *ATTACKS[kind], "-i", f"u{interval_us}", target]


def iperf_tcp_cmd(server, seconds, rate_mbps, port=5201):
    return ["iperf3", "-c", server, "-p", str(port), "-t", str(seconds),
            "-b", f"{rate_mbps}M", "-i", "1", "--json"]


def iperf_udp_cmd(server, seconds, rate_mbps, port=5202):
    return ["iperf3", "-c", server, "-p", str(port), "-u", "-t", str(seconds),
            "-b", f"{rate_mbps}M", "-i", "1", "--json", "--get-server-output"]


def ping_cmd(server, seconds, interval=0.2):
    return ["ping", "-D", "-i", str(interval), "-w", str(seconds), server]
