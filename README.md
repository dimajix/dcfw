# DCFW - The Docker Container Firewall

## What is DCFW?

The Docker Container Firewall is a small Python application, which injects firewall rules into Docker containers.
It's the poor man's alternative to service meshes in Kubernetes clusters.

## What Problem does DCFW solve?

## How is dcfw different from ufw-docker?

## How does DCFW work?

## How can I use DCFW?

## How can I specify container rules?

```
allow|deny|reject [log] [on INTERFACE] [proto PROTOCOL] [from ADDRESS [port PORT] [to ADDRESS [port PORT] [comment COMMENT]
```

* `INTERFACE = eth0, eth1, ...`
* `PROTOCOL = udp, tcp, ...`
* `ADDRESS = 1.2.3.4 or 10.0.0.0/24`
* `PORT = 0-65535`
* `COMMENT = "comment"`

## I don't see any logging!

```shell
sudo sysctl net.netfilter.nf_log_all_netns=1      
```


## Example

```yaml
services:
  firewall:
    image: dimajix/dcfw
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - CAP_NET_ADMIN
      - CAP_KILL
      - CAP_SYS_ADMIN
      - CAP_CHOWN
      - CAP_SETGID
      - CAP_SETUID
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /proc:/host/proc
      - type: tmpfs
        target: /var/run
    command:
      - --proc-dir=/host/proc

  webserver:
    image: httpd:2.2-alpine
    cap_drop:
      - ALL
    cap_add:
      - CAP_CHOWN
      - CAP_SETGID
      - CAP_SETUID
      - CAP_KILL
    labels:
      - dcfw.enable=true
      - dcfw.input.policy=deny
      - dcfw.input.rule.1=allow on eth0 proto tcp from 192.168.110.0/24 to any port 80
      - dcfw.input.rule.2=allow on eth0 proto tcp from 172.16.64.0/24 to any port 80
      - dcfw.output.policy=deny
      - dcfw.output.rule.1=allow proto tcp to 192.168.150.6 port 8080 comment "Allow communication to proxy"
    networks:
      firewall-bridge:
        ipv4_address: 172.16.64.6

  webclient:
    image: ubuntu:24.04
    cap_drop:
      - ALL
    cap_add:
      - CAP_CHOWN
      - CAP_SETGID
      - CAP_SETUID
      - CAP_DAC_OVERRIDE
      - CAP_KILL
    labels:
      - dcfw.enable=true
      - dcfw.input.policy=deny
      - dcfw.output.policy=deny
      - dcfw.output.rule.1=allow proto tcp to 192.168.150.6 port 8080 comment "Allow communication to proxy"
      - dcfw.output.rule.3=allow proto tcp to 172.16.64.6 port 80 comment "Allow communication to web server"
    networks:
      firewall-bridge:
        ipv4_address: 172.16.64.7
```

## What are important limitations of DCFW?

* DCFW currently only supports IP addresses and IP networks in rules. You cannot specify DNS host namaes


## How can I contribute to DCFW?
