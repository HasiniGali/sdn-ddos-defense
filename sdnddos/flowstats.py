"""Turn cumulative OpenFlow flow counters into per-interval deltas.

OpenFlow counters are cumulative per flow *instance*. A flow that idles out and is
re-created restarts at zero, so a naive `new - old` goes negative (and clamping it to
zero, as the original monitor did, silently drops traffic). This tracker:

* keys flows by their match identity,
* treats a counter or duration that went backwards as a new instance,
* folds in final counters reported by OFPFlowRemoved for instances that expired
  between two polls.
"""
from dataclasses import dataclass


@dataclass
class FlowSample:
    key: tuple          # (src, dst, proto); dst/proto are None for drop rules
    packets: int
    bytes: int
    duration: float     # seconds since the flow instance was installed


@dataclass
class FlowDelta:
    key: tuple
    packets: int
    bytes: int
    is_new: bool        # first seen during this interval


class FlowDeltaTracker:
    def __init__(self):
        self._last = {}       # key -> FlowSample from the previous poll
        self._pending = {}    # key -> [packets, bytes] from removed instances

    def flow_removed(self, sample):
        """Record the final counters of an expired/deleted flow instance."""
        prev = self._last.pop(sample.key, None)
        dp = sample.packets - (prev.packets if prev else 0)
        db = sample.bytes - (prev.bytes if prev else 0)
        acc = self._pending.setdefault(sample.key, [0, 0, prev is None])
        acc[0] += max(dp, 0)
        acc[1] += max(db, 0)

    def update(self, samples):
        """Consume one poll's samples; return the deltas since the previous poll."""
        out = {}
        for s in samples:
            prev = self._last.get(s.key)
            restarted = prev is not None and (
                s.packets < prev.packets or s.duration < prev.duration
            )
            if prev is None or restarted:
                dp, db = s.packets, s.bytes
            else:
                dp, db = s.packets - prev.packets, s.bytes - prev.bytes
            out[s.key] = FlowDelta(s.key, dp, db, is_new=prev is None)
            self._last[s.key] = s

        for key, (dp, db, was_unseen) in self._pending.items():
            d = out.get(key)
            if d is None:
                out[key] = FlowDelta(key, dp, db, is_new=was_unseen)
            else:
                d.packets += dp
                d.bytes += db
                # Re-created after expiry: the flow existed before, not new traffic.
                d.is_new = d.is_new and was_unseen
        self._pending.clear()

        # Instances that vanished without a FlowRemoved message are forgotten.
        live = {s.key for s in samples}
        for key in list(self._last):
            if key not in live:
                del self._last[key]
        return list(out.values())
