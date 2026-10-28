"""os-ken (Ryu fork) OpenFlow 1.3 app: L3 learning switch + DDoS detection/mitigation.

Run with:  SDNDDOS_CONFIG=cfg.json python -m sdnddos.run_controller

Flow layout (single table):
  priority 100  ipv4_src=X                    -> drop          (mitigation)
  priority 10   ipv4_src, ipv4_dst, ip_proto  -> output port   (forwarding, idle timeout)
  priority 0    *                             -> controller    (table miss)

Every poll the app turns flow counters into per-source features (ingress switch only,
so multi-hop traffic is not double counted), scores them with every detector in the
model bundle (shadow mode, logged), and lets the active detector drive the block policy.
"""
import csv
import json
import os
import time

import joblib
import numpy as np
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                       MAIN_DISPATCHER, set_ev_cls)
from os_ken.lib import hub
from os_ken.lib.packet import arp, ether_types, ethernet, ipv4, packet
from os_ken.ofproto import ofproto_v1_3

from sdnddos import explain
from sdnddos.config import FEATURES, ControllerConfig
from sdnddos.features import source_features, to_row
from sdnddos.flowstats import FlowDeltaTracker, FlowSample
from sdnddos.mitigation import BLOCK, UNBLOCK, MitigationPolicy

PRIO_DROP, PRIO_FWD, PRIO_MISS = 100, 10, 0


class DDoSDefenseApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = ControllerConfig.from_env()
        os.makedirs(self.cfg.run_dir, exist_ok=True)
        self.datapaths = {}
        self.mac_to_port = {}       # dpid -> {mac: port}
        self.ingress = {}           # src ip -> dpid where it was first seen
        self.trackers = {}          # dpid -> FlowDeltaTracker
        self.last_reply = {}        # dpid -> controller time of previous stats reply
        self.partial = {}           # dpid -> stats bodies of a multipart reply
        self.policy = MitigationPolicy(
            self.cfg.confirm_intervals, self.cfg.min_block_s, self.cfg.quiet_pps,
            self.cfg.quiet_intervals, self.cfg.protected_ips)
        self.detectors = self._load_detectors()
        self._open_logs()
        self.cfg.dump(os.path.join(self.cfg.run_dir, "controller_config.json"))
        hub.spawn(self._poll_loop)

    # ---------------------------------------------------------------- setup

    def _load_detectors(self):
        if not os.path.exists(self.cfg.model_path):
            if self.cfg.active_detector != "none":
                raise FileNotFoundError(self.cfg.model_path)
            return {}
        bundle = joblib.load(self.cfg.model_path)
        names = bundle if self.cfg.shadow else {self.cfg.active_detector}
        return {n: bundle[n] for n in names if n in bundle}

    def _open_logs(self):
        d = self.cfg.run_dir
        names = sorted(self.detectors)
        self._files = []

        def writer(name, header):
            f = open(os.path.join(d, name), "w", newline="")
            self._files.append(f)
            w = csv.writer(f)
            w.writerow(header)
            return w

        self.w_feat = writer("features.csv", ["t", "dpid", "src", "dt", *FEATURES,
                                              *[f"score_{n}" for n in names],
                                              "blocked"])
        self.w_event = writer("events.csv", ["t", "event", "src", "dpid", "detector",
                                             "score", "attribution"])
        self.w_time = writer("timing.csv", ["t", "dpid", "n_sources",
                                            *[f"ms_{n}" for n in names], "ms_total"])
        self.w_flow = writer("flows_removed.csv", ["t", "dpid", "src", "dst", "proto",
                                                   "priority", "duration", "packets",
                                                   "bytes", "reason"])

    def _flush(self):
        for f in self._files:
            f.flush()

    # ------------------------------------------------------------ switching

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.trackers.setdefault(dp.id, FlowDeltaTracker())
        elif dp.id in self.datapaths:
            del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_MISS, parser.OFPMatch(), actions)

    def _add_flow(self, dp, priority, match, actions, idle=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] \
            if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle,
                                      flags=flags))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        ports = self.mac_to_port.setdefault(dp.id, {})
        ports[eth.src] = in_port

        ip = pkt.get_protocol(ipv4.ipv4)
        a = pkt.get_protocol(arp.arp)
        src_ip = ip.src if ip else (a.src_ip if a else None)
        if src_ip:
            # The first switch to report a new source is its ingress switch.
            self.ingress.setdefault(src_ip, dp.id)

        out_port = ports.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if ip and out_port != ofp.OFPP_FLOOD:
            if self.policy.is_blocked(ip.src):
                return
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=ip.src, ipv4_dst=ip.dst,
                                    ip_proto=ip.proto)
            self._add_flow(dp, PRIO_FWD, match, actions,
                           idle=self.cfg.flow_idle_timeout,
                           flags=ofp.OFPFF_SEND_FLOW_REM)
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions,
                                        data=msg.data))

    # ------------------------------------------------------------ statistics

    def _poll_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(self.cfg.poll_interval)

    @staticmethod
    def _sample(stat):
        m = stat.match
        if "ipv4_src" not in m:
            return None
        if stat.priority == PRIO_DROP:
            key = (m["ipv4_src"], None, None)
        elif stat.priority == PRIO_FWD:
            key = (m["ipv4_src"], m["ipv4_dst"], m["ip_proto"])
        else:
            return None
        return FlowSample(key, stat.packet_count, stat.byte_count,
                          stat.duration_sec + stat.duration_nsec / 1e9)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        msg = ev.msg
        s = self._sample(msg)
        if s is None:
            return
        # Same ingress filter as _stats_reply: a transit switch never tracked this
        # flow, so its final counters would be counted as one interval's traffic.
        if self.ingress.get(s.key[0]) == msg.datapath.id:
            tracker = self.trackers.setdefault(msg.datapath.id, FlowDeltaTracker())
            tracker.flow_removed(s)
        self.w_flow.writerow([f"{time.time():.3f}", msg.datapath.id, *s.key,
                              msg.priority, f"{s.duration:.3f}", s.packets, s.bytes,
                              msg.reason])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        self.partial.setdefault(dpid, []).extend(msg.body)
        if msg.flags & msg.datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        body = self.partial.pop(dpid)
        now = time.time()
        prev = self.last_reply.get(dpid)
        self.last_reply[dpid] = now
        samples = [s for s in map(self._sample, body)
                   if s is not None and self.ingress.get(s.key[0]) == dpid]
        deltas = self.trackers[dpid].update(samples)
        if prev is None:
            return
        self._process_interval(now, dpid, now - prev, deltas)

    # ---------------------------------------------------- detection + mitigation

    def _process_interval(self, now, dpid, dt, deltas):
        t0 = time.perf_counter()
        feats = source_features(deltas, dt)
        srcs = sorted(feats)
        names = sorted(self.detectors)
        scores, timing = {}, {}
        if srcs and names:
            X = np.array([to_row(feats[s]) for s in srcs])
            for n in names:
                t1 = time.perf_counter()
                scores[n] = self.detectors[n].score(X)
                timing[n] = (time.perf_counter() - t1) * 1e3

        active = self.detectors.get(self.cfg.active_detector)
        for i, src in enumerate(srcs):
            if active is not None:
                score = scores[active.name][i]
                action = self.policy.step(now, src, score >= active.threshold,
                                          feats[src]["pps"])
                self._apply(action, now, src, dpid, active, score, feats[src])
            self.w_feat.writerow([f"{now:.3f}", dpid, src, f"{dt:.3f}",
                                  *[f"{feats[src][f]:.6g}" for f in FEATURES],
                                  *[f"{scores[n][i]:.6g}" for n in names],
                                  int(self.policy.is_blocked(src))])
        # Blocked sources whose drop rule saw no packets still need a quiet tick.
        if active is not None:
            for src, d in list(self.ingress.items()):
                if d == dpid and src not in feats:
                    self._apply(self.policy.idle(now, src), now, src, dpid, active,
                                None, None)

        total = (time.perf_counter() - t0) * 1e3
        self.w_time.writerow([f"{now:.3f}", dpid, len(srcs),
                              *[f"{timing.get(n, 0):.3f}" for n in names],
                              f"{total:.3f}"])
        self._flush()

    def _apply(self, action, now, src, dpid, det, score, feats):
        if action is None:
            return
        dp = self.datapaths.get(dpid)
        if dp is None:
            return
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
        attribution = ""
        if action == BLOCK:
            self._add_flow(dp, PRIO_DROP, match, [], flags=ofp.OFPFF_SEND_FLOW_REM)
            attr = explain.attributions(det, to_row(feats))
            attribution = json.dumps(attr[:5]) if attr else ""
        elif action == UNBLOCK:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT, priority=PRIO_DROP,
                match=match, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))
        self.w_event.writerow([f"{now:.3f}", action, src, dpid, det.name,
                               "" if score is None else f"{score:.6g}", attribution])
        self.logger.info("%s %s (detector=%s score=%s)", action, src, det.name, score)
