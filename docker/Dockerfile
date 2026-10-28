# Mininet + Open vSwitch + os-ken experiment image.
# OVS uses the host kernel datapath: the host must have the openvswitch module loaded.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        mininet openvswitch-switch openvswitch-common hping3 iperf3 curl iputils-ping \
        iproute2 net-tools ethtool procps psmisc python3 python3-venv python3-pip \
        python3-dev build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# --system-site-packages so the venv also sees the apt-installed mininet package.
RUN python3 -m venv --system-site-packages /opt/venv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install -r /tmp/requirements.txt
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
WORKDIR /work
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
