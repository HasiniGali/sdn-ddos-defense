"""Run one experiment end to end inside the container (needs root).

    python -m sdnddos.orchestrator results/runs/<phase>/<run_id>/spec.json

Timeline (seconds from t0):  [0, warm) benign only | [warm, warm+attack) attack
| [warm+attack, total) benign only. Every timestamp uses the same clock as the
controller, so ground-truth labels line up with controller intervals.
"""
import json
import os
import random
import signal
import socket
import subprocess
import sys
import threading
import time
from functools import partial

import psutil
from mininet.clean import cleanup
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from sdnddos import traffic
from sdnddos.config import CONFIG_ENV, ControllerConfig
from sdnddos.topo import SERVER_IP, DDoSTopo, host_ips

OF_PORT = 6653
WWW = "/tmp/sdnddos_www"


def _wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise RuntimeError(f"controller did not open port {port}")


def _sample_resources(pid, path, stop):
    proc = psutil.Process(pid)
    proc.cpu_percent(None)
    with open(path, "w") as f:
        f.write("t,cpu_percent,rss_mb,sys_cpu_percent\n")
        while not stop.is_set():
            time.sleep(1.0)
            try:
                f.write(f"{time.time():.3f},{proc.cpu_percent(None):.1f},"
                        f"{proc.memory_info().rss / 2**20:.1f},"
                        f"{psutil.cpu_percent(None):.1f}\n")
                f.flush()
            except psutil.NoSuchProcess:
                return


def _start_controller(spec, run_dir):
    cfg = ControllerConfig(run_dir=run_dir, **spec.get("controller", {}))
    cfg.protected_ips = [SERVER_IP]
    cfg_path = os.path.join(run_dir, "controller_input.json")
    cfg.dump(cfg_path)
    env = dict(os.environ, **{CONFIG_ENV: cfg_path, "PYTHONPATH": os.getcwd()})
    log = open(os.path.join(run_dir, "controller.log"), "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "sdnddos.run_controller", "--ofp-tcp-listen-port",
         str(OF_PORT)], env=env, stdout=log, stderr=subprocess.STDOUT)
    _wait_port(OF_PORT)
    return proc


def _prepare_hosts(net):
    for h in net.hosts:
        h.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1 "
              "net.ipv6.conf.default.disable_ipv6=1")
        # Without this, veth hands iperf3 64 KB super-packets (see REVIEW.md H6).
        h.cmd(f"ethtool -K {h.defaultIntf()} tso off gso off gro off")


def run(spec_path):
    with open(spec_path) as f:
        spec = json.load(f)
    run_dir = os.path.dirname(os.path.abspath(spec_path))
    rng = random.Random(spec["seed"])
    warm, att, tail = spec["warm_s"], spec["attack_s"], spec["tail_s"]
    total = warm + att + tail
    link = spec["link"]
    size = spec["size"]
    benign_ips, attacker_ips = host_ips(size)

    cleanup()
    os.makedirs(WWW, exist_ok=True)
    for name, n in traffic.HTTP_FILES.items():
        with open(os.path.join(WWW, name), "wb") as f:
            f.write(os.urandom(n))

    ctrl = _start_controller(spec, run_dir)
    stop = threading.Event()
    sampler = threading.Thread(target=_sample_resources, daemon=True, args=(
        ctrl.pid, os.path.join(run_dir, "resources.csv"), stop))
    sampler.start()

    net = Mininet(topo=DDoSTopo(size=size, bw=link["bw"], delay_ms=link["delay_ms"],
                                loss=link["loss"]),
                  switch=partial(OVSKernelSwitch, protocols="OpenFlow13"),
                  link=TCLink, controller=None, autoSetMacs=True, autoStaticArp=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=OF_PORT)
    procs, logs = [], []
    manifest = {**spec, "status": "running", "attacks": []}

    def popen(host, cmd, name):
        out = open(os.path.join(run_dir, name), "w")
        logs.append(out)
        p = host.popen(cmd, stdout=out, stderr=subprocess.STDOUT)
        procs.append(p)
        return p

    try:
        net.start()
        end = time.time() + 20
        while not all(s.connected() for s in net.switches):
            if time.time() > end:
                raise RuntimeError("switches did not connect")
            time.sleep(0.2)
        _prepare_hosts(net)
        srv = net.get("srv")
        # One ping per host so the controller learns MACs and ingress switches.
        for h in net.hosts:
            if h is not srv:
                h.cmd(f"ping -c1 -W1 {SERVER_IP}")

        py = sys.executable
        popen(srv, [py, "-m", "http.server", "80", "--bind", SERVER_IP,
                    "--directory", WWW], "srv_http.log")
        popen(srv, ["iperf3", "-s", "-p", "5201"], "srv_iperf_tcp.log")
        popen(srv, ["iperf3", "-s", "-p", "5202"], "srv_iperf_udp.log")
        time.sleep(1.0)

        t0 = time.time()
        manifest["t0"] = t0
        think = traffic.BENIGN_LOAD[spec["benign_load"]]
        clients = [(n, think) for n in benign_ips] + \
                  [(n, traffic.ATTACKER_THINK_S) for n in attacker_ips]
        for k, (name, th) in enumerate(clients):
            popen(net.get(name), [py, "-m", "sdnddos.benign_client",
                                  "--server", SERVER_IP, "--think", str(th),
                                  "--duration", str(total), "--seed",
                                  str(spec["seed"] * 100 + k), "--out",
                                  os.path.join(run_dir, f"http_{name}.csv")],
                  f"client_{name}.log")
        bw = link["bw"]
        popen(net.get("b1"), traffic.ping_cmd(SERVER_IP, total), "ping_b1.log")
        popen(net.get("b2"), traffic.iperf_tcp_cmd(SERVER_IP, total, 0.4 * bw),
              "iperf_tcp_b2.json")
        popen(net.get("b3"), traffic.iperf_udp_cmd(SERVER_IP, total, 0.1 * bw),
              "iperf_udp_b3.json")

        attack = spec.get("attack")
        attackers = []
        if attack:
            time.sleep(max(0.0, t0 + warm - time.time()))
            for name, ip in attacker_ips.items():
                time.sleep(rng.uniform(0, 0.3))
                p = popen(net.get(name), traffic.hping3_cmd(
                    attack["type"], attack["pps"], SERVER_IP), f"hping3_{name}.log")
                attackers.append((name, ip, p, time.time()))
            time.sleep(max(0.0, t0 + warm + att - time.time()))
            for name, ip, p, start in attackers:
                p.send_signal(signal.SIGINT)
                manifest["attacks"].append({"host": name, "ip": ip, "start": start,
                                            "end": time.time()})
        # Grace period so iperf3 clients finish and write complete JSON (they start
        # slightly after t0); interrupting them corrupts their output.
        time.sleep(max(0.0, t0 + total - time.time()) + 6.0)
        manifest["t_end"] = time.time()
        manifest["status"] = "done"
    except Exception as e:  # recorded so the runner can retry the run
        manifest["status"] = "failed"
        manifest["error"] = repr(e)
        raise
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
        time.sleep(1.0)
        for p in procs:
            if p.poll() is None:
                p.kill()
        for f in logs:
            f.close()
        net.stop()
        stop.set()
        ctrl.send_signal(signal.SIGINT)
        try:
            ctrl.wait(10)
        except subprocess.TimeoutExpired:
            ctrl.kill()
        with open(os.path.join(run_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        cleanup()


if __name__ == "__main__":
    setLogLevel("warning")
    run(sys.argv[1])
