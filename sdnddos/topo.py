"""Parameterised Mininet topologies.

Addressing: server 10.0.0.100, benign hosts b<i> = 10.0.0.<i>,
attackers a<j> = 10.0.0.<200+j>. Link delay/loss apply to host links; the
inter-switch trunk gets 4x the host bandwidth so the server link stays the bottleneck.
"""
from mininet.topo import Topo

SERVER_IP = "10.0.0.100"

SIZES = {
    # name: (switches, benign hosts, attackers)
    "small": (1, 3, 3),
    "large": (2, 8, 4),
}


def host_ips(size):
    _, n_benign, n_attack = SIZES[size]
    benign = {f"b{i}": f"10.0.0.{i}" for i in range(1, n_benign + 1)}
    attackers = {f"a{j}": f"10.0.0.{200 + j}" for j in range(1, n_attack + 1)}
    return benign, attackers


def ingress_switch(size, ip):
    """dpid of the switch a host is attached to (the server is on s1)."""
    n_sw, _, _ = SIZES[size]
    if ip == SERVER_IP:
        return 1
    benign, attackers = host_ips(size)
    return list({**benign, **attackers}.values()).index(ip) % n_sw + 1


class DDoSTopo(Topo):
    def build(self, size="small", bw=10, delay_ms=2, loss=0.0):
        n_sw, _, _ = SIZES[size]
        benign, attackers = host_ips(size)
        link = dict(bw=bw, delay=f"{delay_ms}ms", loss=loss or None)
        switches = [self.addSwitch(f"s{i}", protocols="OpenFlow13")
                    for i in range(1, n_sw + 1)]
        srv = self.addHost("srv", ip=f"{SERVER_IP}/24")
        self.addLink(srv, switches[0], **link)
        # Alternate hosts across switches so both edges carry benign and attack traffic.
        for name, ip in [*benign.items(), *attackers.items()]:
            h = self.addHost(name, ip=f"{ip}/24")
            self.addLink(h, switches[ingress_switch(size, ip) - 1], **link)
        for a, b in zip(switches, switches[1:]):
            self.addLink(a, b, bw=4 * bw)
