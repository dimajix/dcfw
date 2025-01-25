from typing import Optional

from docker.models.containers import Container
from pydantic import BaseModel


def _parse_optional(args: list[str], keyword: str) -> Optional[str]:
    if len(args) >= 2 and args[0] == keyword:
        result = args[1]
        del args[0]
        del args[0]
    else:
        result = None
    return result


class Rule(BaseModel):
    index: int
    command: str
    interface: Optional[str]
    protocol: Optional[str]
    address: Optional[str]
    port: Optional[int]

    @staticmethod
    def from_string(idx:int, direction:str, rule:str) -> "Rule":
        args = [r for r in rule.split(' ') if len(r) > 1]
        return Rule.from_args(idx, direction, args)

    @staticmethod
    def from_args(idx:int, direction:str, args:list[str]) -> "Rule":
        if len(args) < 2:
            raise Exception(f'Invalid rule format, need at least 2 arguments. Rule: {" ".join(args)}')

        # Parse command
        command = args[0]
        if command not in ['allow', 'deny']:
            raise Exception(f'Invalid rule command: must be "allow" or "deny". Rule: {" ".join(args)}')
        del args[0]

        # Parse optional interface
        interface = _parse_optional(args, 'on')
        protocol = _parse_optional(args, 'proto')

        if direction == 'in':
            address = _parse_optional(args, 'from')
        else:
            address = _parse_optional(args, 'to')

        port = _parse_optional(args, 'port')
        if port is not None:
            port = int(port)

        if direction == 'input':
            return InputRule(index=idx, command=command, interface=interface, protocol=protocol, address=address, port=port)
        else:
            return OutputRule(index=idx, command=command, interface=interface, protocol=protocol, address=address, port=port)


class InputRule(Rule):
    @property
    def direction(self) -> str:
        return "input"


class OutputRule(Rule):
    @property
    def direction(self) -> str:
        return "output"


class Configuration(BaseModel):
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
            return [Rule.from_string(idx, direction, rule) for idx, rule in rules_sorted]

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
        return Configuration.from_labels(labels)
