import logging

from docker.models.containers import Container

from dcfw.config import Configuration
from dcfw.firewall import Firewall

LOG = logging.getLogger(__name__)


def process_container(container: Container):
    config = Configuration.from_container(container)
    if config is not None:
        LOG.info(f"Found firewall configuration in container {container.name}")
        fw = Firewall(config)
        fw.apply(container)
    else:
        LOG.info(f"No firewall configuration found in container {container.name}")
