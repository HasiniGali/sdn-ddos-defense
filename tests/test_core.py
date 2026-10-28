import numpy as np
import pytest

from sdnddos.config import FEATURES
from sdnddos.features import source_features
from sdnddos.flowstats import FlowDeltaTracker, FlowSample
from sdnddos.labels import label_interval
from sdnddos.mitigation import BLOCK, UNBLOCK, MitigationPolicy
from sdnddos.traffic import assert_internal_target, hping3_cmd

K = ("10.0.0.1", "10.0.0.100", 6)
DROP = ("10.0.0.1", None, None)


def deltas_by_key(ds):
    return {d.key: (d.packets, d.bytes, d.is_new) for d in ds}


class TestFlowDeltaTracker:
    def test_new_flow_counts_everything_and_is_new(self):
        t = FlowDeltaTracker()
        assert deltas_by_key(t.update([FlowSample(K, 10, 1000, 1.0)])) == \
            {K: (10, 1000, True)}

    def test_delta_between_polls(self):
        t = FlowDeltaTracker()
        t.update([FlowSample(K, 10, 1000, 1.0)])
        assert deltas_by_key(t.update([FlowSample(K, 25, 2500, 3.0)])) == \
            {K: (15, 1500, False)}

    def test_restart_without_flow_removed_uses_new_counter(self):
        # The original monitor clamped this to 0 and lost 4 packets.
        t = FlowDeltaTracker()
        t.update([FlowSample(K, 10, 1000, 5.0)])
        assert deltas_by_key(t.update([FlowSample(K, 4, 400, 0.5)]))[K][:2] == \
            (4, 400)

    def test_flow_removed_between_polls_is_not_lost(self):
        t = FlowDeltaTracker()
        t.update([FlowSample(K, 10, 1000, 1.0)])
        t.flow_removed(FlowSample(K, 13, 1300, 2.5))
        assert deltas_by_key(t.update([])) == {K: (3, 300, False)}

    def test_removed_then_recreated_in_same_interval(self):
        t = FlowDeltaTracker()
        t.update([FlowSample(K, 10, 1000, 1.0)])
        t.flow_removed(FlowSample(K, 13, 1300, 12.0))
        got = deltas_by_key(t.update([FlowSample(K, 5, 500, 0.4)]))
        assert got == {K: (8, 800, False)}

    def test_vanished_flow_is_forgotten(self):
        t = FlowDeltaTracker()
        t.update([FlowSample(K, 10, 1000, 1.0)])
        t.update([])
        assert deltas_by_key(t.update([FlowSample(K, 2, 200, 0.1)]))[K][2] is True


class TestFeatures:
    def test_aggregates_per_source(self):
        t = FlowDeltaTracker()
        ds = t.update([
            FlowSample(("10.0.0.1", "10.0.0.100", 6), 100, 150_000, 1),
            FlowSample(("10.0.0.1", "10.0.0.100", 1), 100, 10_000, 1),
            FlowSample(("10.0.0.2", "10.0.0.100", 17), 50, 5_000, 1),
        ])
        f = source_features(ds, dt=2.0)
        a = f["10.0.0.1"]
        assert a["pps"] == 100 and a["bps"] == 160_000 * 8 / 2
        assert a["avg_pkt_size"] == 800
        assert (a["n_flows"], a["n_dst"], a["n_proto"], a["new_flows"]) == (2, 1, 2, 2)
        assert (a["frac_tcp"], a["frac_icmp"], a["frac_udp"]) == (0.5, 0.5, 0.0)
        assert set(a) == set(FEATURES)
        assert f["10.0.0.2"]["frac_udp"] == 1.0

    def test_drop_rule_counts_rate_but_not_flows(self):
        t = FlowDeltaTracker()
        f = source_features(t.update([FlowSample(DROP, 1000, 60_000, 1)]), 2.0)
        assert f["10.0.0.1"]["pps"] == 500
        assert f["10.0.0.1"]["n_flows"] == 0

    def test_silent_sources_omitted(self):
        t = FlowDeltaTracker()
        t.update([FlowSample(K, 10, 1000, 1)])
        assert source_features(t.update([FlowSample(K, 10, 1000, 3)]), 2.0) == {}

    def test_rejects_zero_interval(self):
        with pytest.raises(ValueError):
            source_features([], 0)


class TestMitigationPolicy:
    def policy(self, **kw):
        args = dict(confirm_intervals=2, min_block_s=10, quiet_pps=20,
                    quiet_intervals=2, protected_ips=["10.0.0.100"])
        args.update(kw)
        return MitigationPolicy(**args)

    def test_blocks_after_consecutive_flags_only(self):
        p = self.policy()
        assert p.step(0, "a", True, 900) is None
        assert p.step(2, "a", False, 900) is None     # streak broken
        assert p.step(4, "a", True, 900) is None
        assert p.step(6, "a", True, 900) == BLOCK
        assert p.is_blocked("a")

    def test_never_blocks_protected(self):
        p = self.policy(confirm_intervals=1)
        assert p.step(0, "10.0.0.100", True, 1e6) is None

    def test_stays_blocked_while_attacker_still_sends(self):
        p = self.policy(confirm_intervals=1)
        p.step(0, "a", True, 900)
        for t in range(2, 40, 2):
            assert p.step(t, "a", False, 900) is None   # drop counters still busy

    def test_unblocks_after_min_block_and_quiet(self):
        p = self.policy(confirm_intervals=1)
        p.step(0, "a", True, 900)
        assert p.idle(4, "a") is None
        assert p.idle(6, "a") is None          # quiet x2 but min_block not reached
        assert p.idle(10, "a") == UNBLOCK
        assert not p.is_blocked("a")

    def test_repeat_offender_waits_twice_as_long(self):
        p = self.policy(confirm_intervals=1)
        p.step(0, "a", True, 900)
        p.idle(5, "a")
        assert p.idle(10, "a") == UNBLOCK
        assert p.step(12, "a", True, 900) == BLOCK
        assert p.idle(20, "a") is None
        assert p.idle(30, "a") is None
        assert p.idle(32, "a") == UNBLOCK      # 20 s minimum the second time


class TestLabels:
    W = {"10.0.0.201": (100.0, 130.0)}

    @pytest.mark.parametrize("t_end,expected", [
        (99.0, 0), (100.5, 1), (115.0, 1), (131.0, 1), (132.5, 0)])
    def test_overlap(self, t_end, expected):
        assert label_interval("10.0.0.201", t_end, 2.0, self.W) == expected

    def test_benign_source_never_attack(self):
        assert label_interval("10.0.0.1", 115.0, 2.0, self.W) == 0


class TestTrafficSafety:
    def test_refuses_external_targets(self):
        for ip in ["8.8.8.8", "192.168.1.1", "10.0.1.5"]:
            with pytest.raises(ValueError):
                hping3_cmd("udp", 100, ip)

    def test_rate_to_interval(self):
        assert hping3_cmd("syn", 500, "10.0.0.100")[-2] == "u2000"


def test_detectors_registry_fit_and_score():
    from sdnddos.detectors import BUILDERS
    rng = np.random.default_rng(0)
    X = np.abs(rng.normal(size=(200, len(FEATURES)))) * 100
    y = (X[:, 0] > 100).astype(int)
    for name, build in BUILDERS.items():
        d = build(0)
        if name == "threshold":
            d.threshold = 100
        d.fit(X, y)
        s = d.score(X[:5])
        assert s.shape == (5,), name
        assert d.predict(X[:5]).dtype == bool


def test_attributions_shapes():
    from sdnddos.detectors import BUILDERS
    from sdnddos.explain import attributions
    rng = np.random.default_rng(0)
    X = np.abs(rng.normal(size=(200, len(FEATURES)))) * 100
    y = (X[:, 0] > 100).astype(int)
    for name in ["threshold", "dt", "rf", "xgb", "lr"]:
        d = BUILDERS[name](0)
        d.threshold = 100 if name == "threshold" else 0.5
        d.fit(X, y)
        a = attributions(d, X[0])
        assert len(a) == len(FEATURES), name
        if name != "threshold":
            assert a[0][0] == "pps", (name, a[:3])


def test_ingress_switch_matches_topology_plan():
    from sdnddos.topo import SERVER_IP, host_ips, ingress_switch
    benign, attackers = host_ips("small")
    assert {ingress_switch("small", ip) for ip in [*benign.values(),
                                                   *attackers.values()]} == {1}
    benign, attackers = host_ips("large")
    ips = [*benign.values(), *attackers.values()]
    assert [ingress_switch("large", ip) for ip in ips[:4]] == [1, 2, 1, 2]
    assert ingress_switch("large", SERVER_IP) == 1
