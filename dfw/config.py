import logging
from typing import Optional
from docker.models.containers import Container
from pydantic import BaseModel

LOG = logging.getLogger(__name__)


def _parse_optional(args: list[str], keyword: str) -> Optional[str]:
    if len(args) >= 2 and args[0] == keyword:
        result = args[1]
        del args[0]
        del args[0]
    else:
        result = None
    return result

def _parse_address(args: list[str], keyword: str) -> Optional[str]:
    adr = _parse_optional(args, keyword)
    if adr == 'any':
        adr = '0.0.0.0/0'
    return adr


class Rule(BaseModel):
    index: int
    command: str
    interface: Optional[str]
    protocol: Optional[str]
    src_address: Optional[str]
    src_port: Optional[int]
    dst_address: Optional[str]
    dst_port: Optional[int]

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
        interface = _parse_optional(args, 'on')
        protocol = _parse_optional(args, 'proto')

        src_address = _parse_address(args, 'from')
        src_port = None
        if src_address is not None:
            src_port = _parse_optional(args, 'port')
            if src_port is not None:
                src_port = int(src_port)

        dst_address = _parse_address(args, 'to')
        dst_port = None
        if dst_address is not None:
            dst_port = _parse_optional(args, 'port')
            if dst_port is not None:
                dst_port = int(dst_port)

        if len(args) > 0:
            raise Exception(f'Invalid rule format, cannot parse remaining arguments "{" ".join(args)}". Rule: {" ".join(args)}')

        return Rule(index=idx, command=command, interface=interface, protocol=protocol, src_address=src_address, src_port=src_port, dst_address=dst_address, dst_port=dst_port)


class Configuration(BaseModel):
    container_name: Optional[str] = None
    enabled: bool
    input_default: str
    output_default: str
    input_rules: list[Rule]
    output_rules: list[Rule]

    @staticmethod
    def from_labels(labels: dict[str, str]) -> "Configuration":
        def extract_int_key(prefix:str, key: str) -> int:
            return int(key.removeprefix(prefix))

        def parse_rules(direction:str) -> list[Rule]:
            prefix = 'dfw.' + direction + '.rule.'
            rules_raw = [(extract_int_key(prefix, key), label)
                         for key, label in labels.items()
                         if key.startswith(prefix)]
            rules_sorted = sorted(rules_raw, key=lambda item: item[0])
            return [Rule.from_string(idx, rule) for idx, rule in rules_sorted]

        enabled = labels.get('dfw.enabled', False)
        input_default = labels.get('dfw.input.default', 'deny')
        output_default = labels.get('dfw.output.default', 'allow')
        input_rules = parse_rules('input')
        output_rules = parse_rules('output')
        return Configuration(
            enabled=enabled,
            input_default=input_default,
            output_default=output_default,
            input_rules=input_rules,
            output_rules=output_rules
        )

    @staticmethod
    def from_container(container: Container) -> "Configuration":
        labels = container.labels
        config = Configuration.from_labels(labels)
        config.container_name = container.name
        LOG.info(f"{config.container_name} - firewall enabled: {config.enabled}")
        LOG.info(f"{config.container_name} - input default policy: {config.input_default}")
        LOG.info(f"{config.container_name} - output default policy: {config.output_default}")
        for rule in config.input_rules:
            LOG.info(f"{config.container_name} - input rule: {rule}")
        for rule in config.output_rules:
            LOG.info(f"{config.container_name} - output rule: {rule}")

        return config
