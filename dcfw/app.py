import logging

import click
import docker
from docker.models.containers import Container

LOG = logging.getLogger(__name__)


class Application:
    proc_dir: str

    def __init__(self, proc_dir):
        self.proc_dir = proc_dir
        self.client = docker.from_env()

    def run(self) -> None:
        from dcfw.listener import Listener

        self._apply_active_containers()

        listener = Listener(self)
        listener.listen()

    def process_container(self, container: Container) -> None:
        from dcfw.config import Configuration
        from dcfw.firewall import Firewall
        from dcfw.firewall import Namespace

        netns = Namespace.from_container(container, self.proc_dir)
        config = Configuration.from_container(container)
        if config is not None:
            LOG.info(f"Found firewall configuration in container {container.name}")
            fw = Firewall(config)
            netns.execute(fw.apply)
        else:
            LOG.info(f"No firewall configuration found in container {container.name}")

    def _apply_active_containers(self) -> None:
        for container in self.client.containers.list():
            try:
                LOG.info(f"Processing container {container.name}")
                self.process_container(container)
            except Exception as e:
                LOG.error(f'Exception: {e}', exc_info=e)


@click.command()
@click.option('--proc-dir', default='/proc')
def main(proc_dir:str) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    app = Application(proc_dir=proc_dir)
    app.run()

