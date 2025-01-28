import logging
import os
import subprocess
from typing import Optional, Callable

from docker.models.containers import Container
from pyptables import BuiltinChain, UserChain, Tables, Table, Rule, Match, CustomRule
from pyptables.chains import AbstractChain
from pyptables.rules import AbstractRule, CompositeRule
from pyroute2.netns import pushns, popns

from dcfw.config import Configuration, Rule as ConfigRule


LOG = logging.getLogger(__name__)
DCFW_BUILTIN_RULE = 'dcfw builtin rule'
DCFW_USER_RULE = 'dcfw user rule'

NETNS_DIR = '/var/run/netns'
os.makedirs(NETNS_DIR, exist_ok=True)


def rule(iface: Optional[str] = None, oface: Optional[str] = None, proto: Optional[str] = None,
         src: Optional[str] = None, dst: Optional[str] = None, sport: Optional[int] = None, dport: Optional[int] = None,
         match: Optional[str] = None, args: Optional[dict[str, str]] = None, target: str = 'ACCEPT',
         comment: Optional[str] = None) -> Rule:
    kwargs = dict()
    if iface is not None:
        kwargs['in_interface'] = iface
    if oface is not None:
        kwargs['out_interface'] = oface
    if src is not None:
        kwargs['source'] = src
    if dst is not None:
        kwargs['destination'] = dst
    kwargs['jump'] = target
    if proto:
        kwargs['proto'] = proto
        if sport is not None or dport is not None:
            kwargs['match'] = proto
        if sport is not None:
            kwargs['sport'] = str(sport)
        if dport is not None:
            kwargs['dport'] = str(dport)
    if match:
        kwargs['match'] = match
        kwargs.update(args)
    if comment is not None:
        kwargs['comment'] = comment
    return Rule(**kwargs)


def policy(cmd:str) -> str:
    if cmd == 'allow':
        return 'ACCEPT'
    elif cmd == 'deny':
        return 'DROP'
    elif cmd == 'reject':
        return 'REJECT'
    else:
        raise ValueError(f'Unknown policy {cmd}')


class Namespace:
    pid: int
    container_name: str
    proc_dir: str

    def __init__(self, pid: int, container_name: str, proc_dir: str):
        self.pid = pid
        self.container_name = container_name
        self.proc_dir = proc_dir

    def execute(self, fun:Callable) -> None:
        LOG.info(f'{self.container_name} - Entering netns of process {self.pid}')
        link_file = os.path.join(NETNS_DIR, str(self.pid))
        try:
            os.remove(link_file)
        except FileNotFoundError:
            pass
        netns_file = os.path.join(self.proc_dir, str(self.pid), "ns/net")
        os.symlink(netns_file, link_file)

        pushns(str(self.pid))
        try:
            fun()
        finally:
            LOG.info(f'{self.container_name} - Leaving netns of process {self.pid}')
            popns()

    @staticmethod
    def from_container(container: Container, proc_dir:str) -> "Namespace":
        pid = container.attrs['State']['Pid']
        return Namespace(pid=pid, container_name=container.name, proc_dir=proc_dir)


class Firewall:
    config: Configuration

    def __init__(self, config: Configuration):
        self.config = config

    def apply(self) -> None:
        if self.config.enabled:
            self._apply_rules()
        else:
            self._flush()

        subprocess.run(['iptables', '-S'])


    def _flush(self) -> None:
        LOG.info(f'{self.config.container_name} - Remove all current filter tables for container')
        subprocess.run(['iptables', '-t', 'filter', '-F'])

    def _apply_rules(self) -> None:
        # Add all rules from all chains
        LOG.info(f'{self.config.container_name} - Collecting chains and rules from container')
        chains = self._get_chains()
        tables = Tables(Table('filter', *chains))
        txt = tables.to_iptables()
        LOG.debug(txt)

        LOG.info(f'{self.config.container_name} - Applying tables via iptables-restore for container')
        subprocess.run(
            ["iptables-restore", "--table", "filter"],
            input=txt.encode('utf-8'),
        )

    def _get_track_chain(self, policy: str) -> list[Rule]:
        if policy == 'allow':
            return [
                rule(proto='tcp', match='conntrack', args={'ctstate': 'NEW'}, target='ACCEPT',
                     comment=DCFW_BUILTIN_RULE + ' - track new TCP connections'),
                rule(proto='udp', match='conntrack', args={'ctstate': 'NEW'}, target='ACCEPT',
                     comment=DCFW_BUILTIN_RULE + ' - track new UDP connections'),
            ]
        else:
            return []

    @property
    def _allow_log(self):
        return f'-m limit --limit 3/min --limit-burst 10 -j LOG --log-level 6 --log-prefix "[DCFW ALLOW {self.config.container_id[0:12]}] "'

    @property
    def _block_log(self):
        return f'-m limit --limit 3/min --limit-burst 10 -j LOG --log-level 4 --log-prefix "[DCFW BLOCK {self.config.container_id[0:12]}] "'

    def _append_log_rule(self, m:Rule, r:ConfigRule) -> AbstractRule:
        if r.log:
            if r.command == 'deny' or r.command == 'reject':
                log_command = self._block_log
            else:
                log_command = self._allow_log
            m2 = m()
            del m2.arguments.kwargs['jump']
            text = m2.rule_definitions()[0] + f'-m conntrack --ctstate NEW ' + log_command
            log_rule = CustomRule(text)
            return CompositeRule(rules=[log_rule, m])
        else:
            return m

    def _get_input_rule(self, r:ConfigRule) -> AbstractRule:
        comment = r.comment if r.comment is not None else DCFW_USER_RULE
        master_rule = rule(
            proto=r.protocol,
            iface=r.interface,
            src=r.src_address, sport=r.src_port,
            dst=r.dst_address, dport=r.dst_port,
            target=policy(r.command),
            comment=comment
        )
        return self._append_log_rule(master_rule, r)

    def _get_output_rule(self, r:ConfigRule) -> AbstractRule:
        comment = r.comment if r.comment is not None else DCFW_USER_RULE
        master_rule = rule(
            proto=r.protocol,
            oface=r.interface,
            src=r.src_address, sport=r.src_port,
            dst=r.dst_address, dport=r.dst_port,
            target=policy(r.command),
            comment=comment
        )
        return self._append_log_rule(master_rule, r)

    def _get_chains(self) -> list[AbstractChain]:
        dcfw_reject_input = [] if self.config.input_policy == 'allow' else [CustomRule(self._block_log)]
        dfw_track_input = self._get_track_chain(self.config.input_policy)
        dcfw_default_input = [] if self.config.input_policy == 'allow' else [rule(target=policy(self.config.input_policy))]

        dcfw_reject_output = [] if self.config.output_policy == 'allow' else [CustomRule(self._block_log)]
        dfw_track_output = self._get_track_chain(self.config.output_policy)
        dcfw_default_output = [] if self.config.output_policy == 'allow' else [rule(target=policy(self.config.output_policy))]

        return [
            BuiltinChain('INPUT', policy(self.config.input_policy), rules=[
                rule(target='dcfw-before-input'),
                rule(target='dcfw-after-input'),
                rule(target='dcfw-reject-input'),
                rule(target='dcfw-track-input'),
            ]),
            BuiltinChain('OUTPUT', policy(self.config.output_policy), rules=[
                rule(target='dcfw-before-output'),
                rule(target='dcfw-after-output'),
                rule(target='dcfw-reject-output'),
                rule(target='dcfw-track-output'),
            ]),
            BuiltinChain('FORWARD', 'DROP', rules=[]),

            UserChain('dcfw-before-input', comment='dcfw-before-input', rules=[
                rule(iface='lo', target='ACCEPT'),
                rule(match='conntrack', args={'ctstate':'RELATED,ESTABLISHED'}, target='ACCEPT'),
                # rule(match='conntrack', args={'ctstate':'INVALID'}, target='dcfw-logging-deny'),
                rule(match='conntrack', args={'ctstate':'INVALID'}, target='DROP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'3'}, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'4'}, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'11'}, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'12'}, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'8'}, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='udp', sport=67, dport=68, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - allow DHCP'),
                rule(target='dcfw-not-local'),
                rule(proto='udp', dst='224.0.0.251/32', dport=5353, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - accept mDNS requests'),
                rule(proto='udp', dst='239.255.255.250/32', dport=1900, target='ACCEPT', comment=DCFW_BUILTIN_RULE + ' - accept SSDP requests'),
                rule(target='dcfw-user-input')
            ]),
            UserChain('dcfw-user-input', comment='dcfw-user-input', rules=[
                self._get_input_rule(r)
                for r in self.config.input_rules
            ]),
            #UserChain('dcfw-user-logging-input', comment='dcfw-user-logging-input', rules=[]),
            UserChain('dcfw-after-input', comment='dcfw-after-input', rules=[
                rule(proto='udp', dport=137, target='dcfw-default-input'),
                rule(proto='udp', dport=138, target='dcfw-default-input'),
                rule(proto='udp', dport=139, target='dcfw-default-input'),
                rule(proto='tcp', dport=445, target='dcfw-default-input'),
                rule(proto='tcp', dport=137, target='dcfw-default-input'),
                rule(proto='udp', dport=67, target='dcfw-default-input'),
                rule(proto='udp', dport=68, target='dcfw-default-input'),
                rule(match='addrtype', args={'dst-type':'BROADCAST'}, target='dcfw-default-input'),
            ]),
            UserChain('dcfw-reject-input', comment='dcfw-reject-input', rules=dcfw_reject_input),
            UserChain('dcfw-track-input', comment='dcfw-track-input', rules=dfw_track_input),
            UserChain('dcfw-default-input', comment='dcfw-default-input', rules=dcfw_default_input),

            UserChain('dcfw-before-output', comment='dcfw-before-output', rules=[
                rule(oface='lo', target='ACCEPT'),
                rule(match='conntrack', args={'ctstate': 'RELATED,ESTABLISHED'}, target='ACCEPT'),
                rule(target='dcfw-user-output')
            ]),
            UserChain('dcfw-user-output', comment='dcfw-user-output', rules=[
                self._get_output_rule(r)
                for r in self.config.output_rules
            ]),
            #UserChain('dcfw-user-logging-output', comment='dcfw-user-logging-output', rules=[]),
            UserChain('dcfw-after-output', comment='dcfw-after-output', rules=[]),
            UserChain('dcfw-track-output', comment='dcfw-track-output', rules=dfw_track_output),
            UserChain('dcfw-reject-output', comment='dcfw-reject-output', rules=dcfw_reject_output),
            UserChain('dcfw-default-output', comment='dcfw-default-output', rules=dcfw_default_output),

            UserChain('dcfw-not-local', comment='dcfw-not-local - drop traffic not for this host', rules=[
                rule(match='addrtype', args={'dst-type': 'LOCAL'}, target='RETURN', comment=DCFW_BUILTIN_RULE + ' - allow unicast traffic to this host'),
                rule(match='addrtype', args={'dst-type': 'MULTICAST'}, target='RETURN', comment=DCFW_BUILTIN_RULE + ' - allow multicast traffic to this host'),
                rule(match='addrtype', args={'dst-type': 'BROADCAST'}, target='RETURN', comment=DCFW_BUILTIN_RULE + ' - allow broadcast traffic to this host'),
                rule(target='DROP', comment=DCFW_BUILTIN_RULE + ' - drop traffic not for this host'),
            ]),
        ]
