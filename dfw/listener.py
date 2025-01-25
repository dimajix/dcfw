from typing import Any
import logging
from docker import DockerClient

from dfw.config import Configuration
from dfw.firewall import Firewall

LOG = logging.getLogger(__name__)


class Listener:
    client: DockerClient

    def __init__(self, client: DockerClient) -> None:
        self.client = client

    def listen(self) -> None:
        for event in self.client.events(decode=True):
            try:
                self._process_event(event)
            except Exception as e:
                LOG.warning(f'Exception: {e}', exc_info=e)

    def _process_event(self, event: dict[str, Any]) -> None:
        event_type = event['Type']
        if event_type == 'network':
            self._process_network_event(event)

    def _process_network_event(self, event: dict[str, Any]) -> None:
        LOG.debug(f"Received network event: {event}")
        action = event['Action']
        network_id = event['Actor']['ID']
        container_id = event['Actor']['Attributes']['container']
        container = self.client.containers.get(container_id)
        LOG.info(f"Container {container.name} {action} to/from network {network_id[0:12]}")

        pid = container.attrs['State']['Pid']
        if pid != 0 and action == 'connect':
            config = Configuration.from_container(container)
            fw = Firewall(config)
            fw.apply(container)
