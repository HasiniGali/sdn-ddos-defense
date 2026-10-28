"""Block/unblock policy, independent of OpenFlow so it can be unit-tested.

    ALLOWED --(flagged for `confirm_intervals` polls in a row)--> BLOCKED
    BLOCKED --(blocked >= min_block AND dropped pps < quiet_pps
               for `quiet_intervals` polls in a row)--> ALLOWED

Unblocking reads the drop rule's own counters: a blocked source looks silent on its
forwarding flows because its packets are dropped, so "the source looks quiet" must be
judged on what it still *sends*, not on what gets through. A source that is blocked
again doubles its minimum block time.
"""
from dataclasses import dataclass

BLOCK, UNBLOCK = "block", "unblock"


@dataclass
class _State:
    streak: int = 0
    blocked_at: float = None
    quiet: int = 0
    min_block: float = 0.0
    offences: int = 0


class MitigationPolicy:
    def __init__(self, confirm_intervals=2, min_block_s=10.0, quiet_pps=20.0,
                 quiet_intervals=2, protected_ips=()):
        self.confirm = confirm_intervals
        self.min_block = min_block_s
        self.quiet_pps = quiet_pps
        self.quiet_intervals = quiet_intervals
        self.protected = set(protected_ips)
        self._s = {}

    def is_blocked(self, src):
        s = self._s.get(src)
        return s is not None and s.blocked_at is not None

    def step(self, now, src, flagged, pps):
        """Feed one interval for one source; return BLOCK, UNBLOCK or None."""
        s = self._s.setdefault(src, _State())
        if s.blocked_at is None:
            if src in self.protected:
                return None
            s.streak = s.streak + 1 if flagged else 0
            if s.streak >= self.confirm:
                s.offences += 1
                s.blocked_at = now
                s.min_block = self.min_block * 2 ** (s.offences - 1)
                s.streak = s.quiet = 0
                return BLOCK
            return None
        s.quiet = s.quiet + 1 if pps < self.quiet_pps else 0
        if now - s.blocked_at >= s.min_block and s.quiet >= self.quiet_intervals:
            s.blocked_at = None
            s.quiet = 0
            return UNBLOCK
        return None

    def idle(self, now, src):
        """A blocked source sent nothing at all this interval (no counter moved)."""
        if self.is_blocked(src):
            return self.step(now, src, False, 0.0)
        return None
