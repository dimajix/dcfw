from typing import Any
import logging
from docker import DockerClient

from dcfw import process_container
from dcfw.config import Configuration
from dcfw.firewall import Firewall

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
        if event['Type'] == 'network' and event['Action'] == 'connect':
            self._process_network_connect_event(event)

    def _process_network_connect_event(self, event: dict[str, Any]) -> None:
        LOG.debug(f"Received network event: {event}")
        network_id = event['Actor']['ID']
        container_id = event['Actor']['Attributes']['container']
        container = self.client.containers.get(container_id)
        LOG.info(f"Container connect to/from network {network_id[0:12]}")
        process_container(container)
