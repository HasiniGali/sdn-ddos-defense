"""Ground-truth labels for controller intervals, from the orchestrator's attack log."""


def attack_windows(manifest):
    """{attacker_ip: (start, end)} from a run manifest."""
    return {a["ip"]: (a["start"], a["end"]) for a in manifest.get("attacks", [])}


def label_interval(src, t_end, dt, windows):
    """1 if the source was attacking at any point inside (t_end - dt, t_end]."""
    w = windows.get(src)
    if w is None:
        return 0
    start, end = w
    return int(t_end > start and t_end - dt < end)
