import logging
import os
import subprocess
from typing import Optional, Callable

import iptc
from docker.models.containers import Container
from pyroute2.netns import pushns, popns

from dfw.config import Configuration


LOG = logging.getLogger(__name__)

NETNS_DIR = '/var/run/netns'
os.makedirs(NETNS_DIR, exist_ok=True)


def with_netns(container: Container, fun: Callable):
    pid = container.attrs['State']['Pid']
    LOG.info(f'Entering netns of process {pid} for container {container.name}')
    link_file = os.path.join("/var/run/netns", str(pid))
    try:
        os.remove(link_file)
    except FileNotFoundError:
        pass
    netns_file = os.path.join("/proc", str(pid), "ns/net")
    os.symlink(netns_file, link_file)

    pushns(str(pid))
    try:
        subprocess.run(['iptables', '-S'])
        fun()
        subprocess.run(['iptables', '-S'])
    finally:
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

    def _flush(self):
        LOG.info('Flushing all current filter tables')
        table = iptc.Table(iptc.Table.FILTER)
        table.refresh()
        table.flush()

    def _apply_rules(self):
        # Flush all existing chains
        LOG.info('Flushing all current filter tables')
        table = iptc.Table(iptc.Table.FILTER)
        table.refresh()
        table.flush()

        # Create all chains
        LOG.info('Creating new filter chains')
        for name in self._get_chain_names():
            if not table.builtin_chain(name):
                table.create_chain(name)

        # Set default policies
        LOG.info('Setting up default policies')
        table.set_policy('INPUT', 'ACCEPT' if self.config.input_default == 'allow' else 'DROP')
        table.set_policy('OUTPUT', 'ACCEPT' if self.config.output_default == 'allow' else 'DROP')
        table.set_policy('FORWARD', 'ACCEPT')

        # Add all rules from all chains
        LOG.info('Appending all rules into the filter chains')
        chains = self._get_chains()
        ipt_chains = table.chains
        for name,chain in chains.items():
            ipt_chain = None
            for c in ipt_chains:
                if c.name == name:
                    ipt_chain = c
                    break
            if ipt_chain is None:
                raise RuntimeError(f'Chain {name} not found')

            for rule in chain:
                LOG.info(f'Appending rule: {rule}')
                ipt_chain.append_rule(rule)

    def _get_chain_names(self) -> list[str]:
        return [
            'INPUT',
            'OUTPUT',
            'dfw-before-input',
            'dfw-after-input',
            'dfw-user-input',
            'dfw-track-input',
            'dfw-default-input',
            'dfw-before-output',
            'dfw-after-output',
            'dfw-user-output',
            'dfw-track-output',
            'dfw-default-output',
            'dfw-not-local'
        ]


    def _get_chains(self) -> dict[str, list[iptc.Rule]]:
        def rule(iface:Optional[str]=None, oface:Optional[str]=None, proto:Optional[str]=None, src:Optional[str]=None, dst:Optional[str]=None, sport:Optional[int]=None, dport:Optional[int]=None, match:Optional[str]=None, args:Optional[dict[str,str]]=None, target:str='ACCEPT'):
            rule = iptc.Rule()
            if iface:
                rule.in_interface = iface
            if oface:
                rule.out_interface = oface
            rule.target = iptc.Target(rule, target)
            if src is not None:
                rule.set_src(src)
            if dst is not None:
                rule.set_dst(dst)
            if proto:
                rule.protocol = proto
                if sport is not None or dport is not None:
                    m = iptc.Match(rule, proto)
                    if sport is not None:
                        m.set_parameter('sport', str(sport))
                    if dport is not None:
                        m.set_parameter('dport', str(dport))
            elif match:
                m = iptc.Match(rule, match)
                for k, v in args.items():
                    m.set_parameter(k, v)
            return rule

        return {
            'INPUT' : [
                rule(target='dfw-before-input'),
                rule(target='dfw-after-input'),
                #rule(target='dfw-reject-input'),
                rule(target='dfw-track-input'),
            ],
            'OUTPUT': [
                rule(target='dfw-before-output'),
                rule(target='dfw-after-output'),
                #rule(target='dfw-reject-output'),
                rule(target='dfw-track-output'),
            ],

            'dfw-before-input': [
                rule(iface='lo', target='ACCEPT'),
                rule(match='conntrack', args={'ctstate':'RELATED,ESTABLISHED'}, target='ACCEPT'),
                rule(match='conntrack', args={'ctstate':'INVALID'}, target='DROP'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'3'}, target='ACCEPT'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'4'}, target='ACCEPT'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'11'}, target='ACCEPT'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'12'}, target='ACCEPT'),
                rule(proto='icmp', match='icmp', args={'icmp-type':'8'}, target='ACCEPT'),
                rule(proto='udp', sport=67, dport=68, target='ACCEPT'),
                rule(target='dfw-not-local'),
                rule(proto='udp', dst='224.0.0.251/32', dport=5353, target='ACCEPT'),
                rule(proto='udp', dst='239.255.255.250/32', dport=1900, target='ACCEPT'),
                rule(target='dfw-user-input')
            ],
            'dfw-user-input': [
                rule(proto=r.protocol, iface=r.interface, src=r.address, dport=r.port, target='ACCEPT' if r.command=='allow' else 'DROP')
                for r in self.config.input_rules
            ],
            'dfw-after-input': [
                rule(proto='udp', dport=137, target='dfw-default-input'),
                rule(proto='udp', dport=138, target='dfw-default-input'),
                rule(proto='udp', dport=139, target='dfw-default-input'),
                rule(proto='tcp', dport=445, target='dfw-default-input'),
                rule(proto='tcp', dport=137, target='dfw-default-input'),
                rule(proto='udp', dport=67, target='dfw-default-input'),
                rule(proto='udp', dport=68, target='dfw-default-input'),
                rule(match='addrtype', args={'dst-type':'BROADCAST'}, target='dfw-default-input'),
            ],
            'dfw-track-input': [],
            'dfw-default-input': [
                rule(target='ACCEPT' if self.config.input_default == 'allow' else 'DROP')
            ],

            'dfw-before-output': [],
            'dfw-user-output': [
                rule(proto=r.protocol, iface=r.interface, dst=r.address, dport=r.port, target='ACCEPT' if r.command=='allow' else 'DROP')
                for r in self.config.output_rules
            ],
            'dfw-track-output': [
                rule(proto='tcp', match='conntrack', args={'ctstate': 'NEW'}, target='ACCEPT'),
                rule(proto='udp', match='conntrack', args={'ctstate': 'NEW'}, target='ACCEPT'),
            ],
            'dfw-default-output': [
                rule(target='ACCEPT' if self.config.output_default == 'allow' else 'DROP')
            ],

            'dfw-not-local': [
                rule(match='addrtype', args={'dst-type': 'LOCAL'}, target='RETURN'),
                rule(match='addrtype', args={'dst-type': 'MULTICAST'}, target='RETURN'),
                rule(match='addrtype', args={'dst-type': 'BROADCAST'}, target='RETURN'),
                rule(target='DROP')
            ],
        }
