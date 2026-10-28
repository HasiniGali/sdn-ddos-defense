#!/bin/bash
# Run a command inside the experiment container (privileged: Mininet needs netns + OVS).
# The container has no network (--network none): emulated attack traffic cannot leave it.
cd "$(dirname "$0")/.."
sudo modprobe openvswitch || exit 1
docker run --rm --privileged --network none \
    -v "$PWD":/work -v /lib/modules:/lib/modules:ro -e PYTHONPATH=/work \
    --name "sdnddos-${SDNDDOS_WORKER:-0}" sdnddos:dev "$@"
rc=$?
# The container runs as root; hand result files back to the invoking user.
sudo chown -R "$(id -u):$(id -g)" results models 2>/dev/null
exit $rc
