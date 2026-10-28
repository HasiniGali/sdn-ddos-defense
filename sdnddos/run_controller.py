"""Launch the controller app (os-ken 4.x ships no `osken-manager` CLI).

    python -m sdnddos.run_controller [--ofp-tcp-listen-port 6653]

Mirrors what ryu-manager did: monkey-patch eventlet first, parse the os-ken
options, then run the OpenFlow handler together with our app.
"""
import sys

from os_ken.lib import hub

hub.patch(thread=False)

from os_ken import cfg  # noqa: E402
from os_ken.base.app_manager import AppManager  # noqa: E402


def main():
    cfg.CONF(args=sys.argv[1:], project="os_ken")
    AppManager.run_apps(["os_ken.controller.ofp_handler", "sdnddos.controller_app"])


if __name__ == "__main__":
    main()
