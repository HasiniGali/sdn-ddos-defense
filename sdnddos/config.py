"""Shared constants and the controller configuration."""
import json
import os
from dataclasses import asdict, dataclass, field

# Per-source features computed by the controller every polling interval.
# Order matters: models are trained on columns in exactly this order.
FEATURES = [
    "pps",           # packets/s sent by the source (forwarded + dropped)
    "bps",           # bits/s sent by the source
    "avg_pkt_size",  # bytes per packet over the interval
    "n_flows",       # active (src, dst, proto) flows in the interval
    "n_dst",         # distinct destinations in the interval
    "n_proto",       # distinct IP protocols in the interval
    "new_flows",     # flows first seen in the interval (packet-in pressure)
    "frac_tcp",      # share of the source's packets that are TCP
    "frac_udp",
    "frac_icmp",
]

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1

CONFIG_ENV = "SDNDDOS_CONFIG"


@dataclass
class ControllerConfig:
    run_dir: str = "results/runs/dev"
    poll_interval: float = 2.0
    flow_idle_timeout: int = 10
    # Detector that drives mitigation: "none" or a key of the model bundle.
    active_detector: str = "none"
    # Run every detector in the bundle on every interval and log its output.
    shadow: bool = True
    model_path: str = "models/detectors.joblib"
    # Mitigation policy (see sdnddos/mitigation.py).
    confirm_intervals: int = 2
    min_block_s: float = 10.0
    quiet_pps: float = 20.0
    quiet_intervals: int = 2
    protected_ips: list = field(default_factory=list)

    @classmethod
    def from_env(cls):
        path = os.environ.get(CONFIG_ENV)
        if not path:
            return cls()
        with open(path) as f:
            return cls(**json.load(f))

    def dump(self, path):
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)
