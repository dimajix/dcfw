import logging
from typing import Optional
from docker.models.containers import Container
from pydantic import BaseModel

LOG = logging.getLogger(__name__)


def _parse_kv(args: list[str], keyword: str) -> Optional[str]:
    if len(args) >= 2 and args[0] == keyword:
        del args[0]
        result = args[0]
        del args[0]
        # Handle quotes
        if result[0] == '"':
            result = result[1:]
            while result[-1] != '"':
                result = result + ' ' + args[0]
                del args[0]
            if result[-1] == '"':
                result = result[:-1]
    else:
        result = None
    return result

def _parse_option(args: list[str], keyword: str) -> bool:
    if len(args) >= 1 and args[0] == keyword:
        del args[0]
        return True
    else:
        return False

def _parse_address(args: list[str], keyword: str) -> Optional[str]:
    adr = _parse_kv(args, keyword)
    if adr == 'any':
        adr = '0.0.0.0/0'
    return adr


class Rule(BaseModel):
    index: int
    command: str
    log: bool = False
    comment: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    src_address: Optional[str] = None
    src_port: Optional[int] = None
    dst_address: Optional[str] = None
    dst_port: Optional[int] = None

    @staticmethod
    def from_string(idx:int, rule:str) -> "Rule":
        args = [r for r in rule.split(' ') if len(r) > 1]
        return Rule.from_args(idx, args)

    @staticmethod
    def from_args(idx:int, args:list[str]) -> "Rule":
        if len(args) < 2:
            raise Exception(f'Invalid rule format, need at least 2 arguments. Rule: {" ".join(args)}')

        # Parse command
        command = args[0]
        if command not in ['allow', 'deny', 'reject']:
            raise Exception(f'Invalid rule command: must be "allow", "deny" or "reject". Rule: {" ".join(args)}')
        del args[0]

        # Parse optional interface
        interface = _parse_kv(args, 'on')
        protocol = _parse_kv(args, 'proto')
        log = _parse_option(args, 'log')

        src_address = _parse_address(args, 'from')
        src_port = None
        if src_address is not None:
            src_port = _parse_kv(args, 'port')
            if src_port is not None:
                src_port = int(src_port)

        dst_address = _parse_address(args, 'to')
        dst_port = None
        if dst_address is not None:
            dst_port = _parse_kv(args, 'port')
            if dst_port is not None:
                dst_port = int(dst_port)

        comment = _parse_kv(args, 'comment')

        if len(args) > 0:
            raise Exception(f'Invalid rule format, cannot parse remaining arguments "{" ".join(args)}". Rule: {" ".join(args)}')

        return Rule(index=idx, command=command, interface=interface, protocol=protocol, log=log, src_address=src_address, src_port=src_port, dst_address=dst_address, dst_port=dst_port, comment=comment)


class Configuration(BaseModel):
    container_name: Optional[str] = None
    enabled: bool
    input_policy: str
    output_policy: str
    input_rules: list[Rule]
    output_rules: list[Rule]

    @staticmethod
    def from_labels(labels: dict[str, str]) -> "Configuration":
        def extract_int_key(prefix:str, key: str) -> int:
            return int(key.removeprefix(prefix))

        def parse_rules(direction:str) -> list[Rule]:
            prefix = 'dcfw.' + direction + '.rule.'
            rules_raw = [(extract_int_key(prefix, key), label)
                         for key, label in labels.items()
                         if key.startswith(prefix)]
            rules_sorted = sorted(rules_raw, key=lambda item: item[0])
            return [Rule.from_string(idx, rule) for idx, rule in rules_sorted]

        enabled = labels.get('dcfw.enable', False)
        input_policy = labels.get('dcfw.input.policy', 'deny')
        output_policy = labels.get('dcfw.output.policy', 'allow')
        input_rules = parse_rules('input')
        output_rules = parse_rules('output')
        return Configuration(
            enabled=enabled,
            input_policy=input_policy,
            output_policy=output_policy,
            input_rules=input_rules,
            output_rules=output_rules
        )

    @staticmethod
    def from_container(container: Container) -> Optional["Configuration"]:
        labels = container.labels
        if 'dcfw.enable' not in labels:
            return None

        config = Configuration.from_labels(labels)
        config.container_name = container.name
        LOG.info(f"{config.container_name} - firewall enabled: {config.enabled}")
        LOG.info(f"{config.container_name} - input default policy: {config.input_policy}")
        LOG.info(f"{config.container_name} - output default policy: {config.output_policy}")
        for rule in config.input_rules:
            LOG.info(f"{config.container_name} - input rule: {rule}")
        for rule in config.output_rules:
            LOG.info(f"{config.container_name} - output rule: {rule}")

        return config
