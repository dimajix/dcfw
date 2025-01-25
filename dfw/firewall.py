import logging
import os
import subprocess
import pyptables
from typing import Optional, Callable

from docker.models.containers import Container
from pyptables import BuiltinChain, UserChain, Tables, Table
from pyptables.chains import AbstractChain
from pyroute2.netns import pushns, popns

from dfw.config import Configuration


LOG = logging.getLogger(__name__)
DFW_BUILTIN_RULE = 'dfw builtin rule'
DFW_USER_RULE = 'dfw user rule'

NETNS_DIR = '/var/run/netns'
os.makedirs(NETNS_DIR, exist_ok=True)


def rule(iface: Optional[str] = None, oface: Optional[str] = None, proto: Optional[str] = None,
         src: Optional[str] = None, dst: Optional[str] = None, sport: Optional[int] = None, dport: Optional[int] = None,
         match: Optional[str] = None, args: Optional[dict[str, str]] = None, target: str = 'ACCEPT',
         comment: Optional[str] = None):
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
    return pyptables.Rule(**kwargs)


def policy(cmd:str) -> str:
    if cmd == 'allow':
        return 'ACCEPT'
    elif cmd == 'deny':
        return 'DROP'
    elif cmd == 'reject':
        return 'REJECT'
    else:
        raise ValueError(f'Unknown policy {cmd}')


def with_netns(container: Container, fun: Callable):
    pid = container.attrs['State']['Pid']
    LOG.info(f'{container.name} - Entering netns of process {pid}')
    link_file = os.path.join("/var/run/netns", str(pid))
    try:
        os.remove(link_file)
    except FileNotFoundError:
        pass
    netns_file = os.path.join("/proc", str(pid), "ns/net")
    os.symlink(netns_file, link_file)

    pushns(str(pid))
    try:
        fun()
    finally:
        LOG.info(f'{container.name} - Leaving netns of process {pid}')
        popns()



class Firewall:
    config: Configuration

    def __init__(self, config: Configuration):
        self.config = config

    def apply(self, container: Container):
        with_netns(container, self._apply)

    def _apply(self):
        if self.config.enabled:
            self._apply_rules()
        else:
            self._flush()

        subprocess.run(['iptables', '-S'])


    def _flush(self):
        LOG.info(f'{self.config.container_name} - Remove all current filter tables for container')
        subprocess.run(['iptables', '-t', 'filter', '-F'])

    def _apply_rules(self):
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

    def _get_track_chain(self, policy: str):
        if policy == 'allow':
            return [
                rule(proto='tcp', match='conntrack', args={'ctstate': 'NEW'}, target='ACCEPT',
                     comment=DFW_BUILTIN_RULE + ' - track new TCP connections'),
                rule(proto='udp', match='conntrack', args={'ctstate': 'NEW'}, target='ACCEPT',
                     comment=DFW_BUILTIN_RULE + ' - track new UDP connections'),
            ]
        else:
            return []

    def _get_chains(self) -> list[AbstractChain]:
        dfw_track_input = self._get_track_chain(self.config.input_default)
        dfw_track_output = self._get_track_chain(self.config.output_default)

        return [
            BuiltinChain('INPUT', policy(self.config.input_default), rules=[
                rule(target='dfw-before-input'),
                rule(target='dfw-after-input'),
                #rule(target='dfw-reject-input'),
                rule(target='dfw-track-input'),
            ]),
            BuiltinChain('OUTPUT', policy(self.config.output_default), rules=[
                rule(target='dfw-before-output'),
                rule(target='dfw-after-output'),
                #rule(target='dfw-reject-output'),
                rule(target='dfw-track-output'),
            ]),
            BuiltinChain('FORWARD', 'DROP', rules=[]),

            UserChain('dfw-before-input', comment='dfw-before-input', rules=[
                rule(iface='lo', target='ACCEPT'),
                rule(match='conntrack', args={'ctstate':'RELATED,ESTABLISHED'}, target='ACCEPT'),
                rule(match='conntrack', args={'ctstate':'INVALID'}, target='DROP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'3'}, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'4'}, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'11'}, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'12'}, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'8'}, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - allow ICMP'),
                rule(proto='udp', sport=67, dport=68, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - allow DHCP'),
                rule(target='dfw-not-local'),
                rule(proto='udp', dst='224.0.0.251/32', dport=5353, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - accept mDNS requests'),
                rule(proto='udp', dst='239.255.255.250/32', dport=1900, target='ACCEPT', comment=DFW_BUILTIN_RULE + ' - accept SSDP requests'),
                rule(target='dfw-user-input')
            ]),
            UserChain('dfw-user-input', comment='dfw-user-input', rules=[
                rule(proto=r.protocol, iface=r.interface, src=r.src_address, sport=r.src_port, dst=r.dst_address, dport=r.dst_port, target=policy(r.command), comment=DFW_USER_RULE)
                for r in self.config.input_rules
            ]),
            UserChain('dfw-after-input', comment='dfw-after-input', rules=[
                rule(proto='udp', dport=137, target='dfw-default-input'),
                rule(proto='udp', dport=138, target='dfw-default-input'),
                rule(proto='udp', dport=139, target='dfw-default-input'),
                rule(proto='tcp', dport=445, target='dfw-default-input'),
                rule(proto='tcp', dport=137, target='dfw-default-input'),
                rule(proto='udp', dport=67, target='dfw-default-input'),
                rule(proto='udp', dport=68, target='dfw-default-input'),
                rule(match='addrtype', args={'dst-type':'BROADCAST'}, target='dfw-default-input'),
            ]),
            UserChain('dfw-track-input', comment='dfw-track-input', rules=dfw_track_input),
            UserChain('dfw-default-input', comment='dfw-default-input', rules=[
                rule(target=policy(self.config.input_default))
            ]),

            UserChain('dfw-before-output', comment='dfw-before-output', rules=[
                rule(oface='lo', target='ACCEPT'),
                rule(match='conntrack', args={'ctstate': 'RELATED,ESTABLISHED'}, target='ACCEPT'),
                rule(target='dfw-user-output')
            ]),
            UserChain('dfw-user-output', comment='dfw-user-output', rules=[
                rule(proto=r.protocol, oface=r.interface, src=r.src_address, sport=r.src_port, dst=r.dst_address, dport=r.dst_port, target=policy(r.command), comment=DFW_USER_RULE)
                for r in self.config.output_rules
            ]),
            UserChain('dfw-after-output', comment='dfw-after-output', rules=[]),
            UserChain('dfw-track-output', comment='dfw-track-output', rules=dfw_track_output),
            UserChain('dfw-default-output', comment='dfw-default-output', rules=[
                rule(target=policy(self.config.output_default))
            ]),

            UserChain('dfw-not-local', comment='dfw-not-local - drop traffic not for this host', rules=[
                rule(match='addrtype', args={'dst-type': 'LOCAL'}, target='RETURN', comment=DFW_BUILTIN_RULE + ' - allow unicast traffic to this host'),
                rule(match='addrtype', args={'dst-type': 'MULTICAST'}, target='RETURN', comment=DFW_BUILTIN_RULE + ' - allow multicast traffic to this host'),
                rule(match='addrtype', args={'dst-type': 'BROADCAST'}, target='RETURN', comment=DFW_BUILTIN_RULE + ' - allow broadcast traffic to this host'),
                rule(target='DROP', comment=DFW_BUILTIN_RULE + ' - drop traffic not for this host'),
            ]),
        ]
