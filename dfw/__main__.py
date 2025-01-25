import logging
import sys

import docker

from dfw.config import Configuration
from dfw.firewall import Firewall
from dfw.listener import Listener

LOG = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    client = docker.from_env()

    for container in client.containers.list():
        LOG.info(f"Processing container {container.name}")
        config = Configuration.from_container(container)
        fw = Firewall(config)
        fw.apply(container)

    # Now watch for changes
    listener = Listener(client)
    listener.listen()


if __name__ == '__main__':
    sys.exit(main())
