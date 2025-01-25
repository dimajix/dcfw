import os
from os import mkdir
from time import sleep
from typing import Any
import logging
import docker
from docker import DockerClient

import dfw.firewall as firewall
from dfw.config import Configuration

LOG = logging.getLogger(__name__)


def process_event(client:DockerClient, event:dict[str, Any]) -> None:
    event_type = event['Type']
    if event_type == 'network':
        LOG.debug(f"Received network event: {event}")
        action = event['Action']
        network_id = event['Actor']['ID']
        container_id = event['Actor']['Attributes']['container']
        container = client.containers.get(container_id)
        LOG.info(f"Container {container.name} {action} to/from network {network_id[0:12]}")

        pid = container.attrs['State']['Pid']
        if pid != 0 and action == 'connect':
            config = Configuration.from_container(container)
            LOG.info(f"Container {container.name} input default policy: {config.input_default}")
            for rule in config.input_rules:
                LOG.info(f"Container {container.name} input rule: {rule}")
            LOG.info(f"Container {container.name} output default policy: {config.output_default}")
            for rule in config.output_rules:
                LOG.info(f"Container {container.name} output rule: {rule}")

            fw = firewall.Firewall(config)
            fw.apply(container)


def listen():
    client = docker.from_env()

    for event in client.events(decode=True):
        try:
            process_event(client, event)
        except Exception as e:
            LOG.warning(f'Exception: {e}', exc_info=e)
