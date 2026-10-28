"""Aggregate per-flow deltas into per-source feature vectors."""
from collections import defaultdict

from sdnddos.config import FEATURES, PROTO_ICMP, PROTO_TCP, PROTO_UDP


def source_features(deltas, dt):
    """Return {src_ip: {feature: value}} for one polling interval of length dt.

    Drop rules have key (src, None, None): their packets count towards the source's
    rate (a blocked attacker is still sending) but not towards flow/dst/proto counts.
    Sources that sent nothing in the interval are omitted.
    """
    if dt <= 0:
        raise ValueError("interval must be positive")
    acc = defaultdict(lambda: {"pkts": 0, "bytes": 0, "flows": 0, "new": 0,
                               "dsts": set(), "protos": set(),
                               "by_proto": defaultdict(int)})
    for d in deltas:
        if d.packets <= 0:
            continue
        src, dst, proto = d.key
        a = acc[src]
        a["pkts"] += d.packets
        a["bytes"] += d.bytes
        if dst is None:
            continue
        a["flows"] += 1
        a["new"] += int(d.is_new)
        a["dsts"].add(dst)
        a["protos"].add(proto)
        a["by_proto"][proto] += d.packets

    out = {}
    for src, a in acc.items():
        pkts = a["pkts"]
        classified = sum(a["by_proto"].values()) or 1
        out[src] = {
            "pps": pkts / dt,
            "bps": a["bytes"] * 8 / dt,
            "avg_pkt_size": a["bytes"] / pkts,
            "n_flows": a["flows"],
            "n_dst": len(a["dsts"]),
            "n_proto": len(a["protos"]),
            "new_flows": a["new"],
            "frac_tcp": a["by_proto"][PROTO_TCP] / classified,
            "frac_udp": a["by_proto"][PROTO_UDP] / classified,
            "frac_icmp": a["by_proto"][PROTO_ICMP] / classified,
        }
    return out


def to_row(feats):
    return [feats[f] for f in FEATURES]
