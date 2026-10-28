#!/bin/bash
# Start OVS daemons inside the container, then run the given command.
set -e
mkdir -p /var/run/openvswitch /var/log/openvswitch
/usr/share/openvswitch/scripts/ovs-ctl start --system-id=random >/dev/null
exec "$@"
