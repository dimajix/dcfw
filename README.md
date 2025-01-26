# DCFW - The Docker Container Firewall

## What is DCFW?

The Docker Container Firewall is a small Python application, which injects firewall rules into Docker containers.
It's the poor man's alternative to Kubernetes service meshes.

## What Problem does DCFW solve?

## How does DCFW work?

## How can I use DCFW?

## What can I specify container rules?

```
allow|deny|reject [on INTERFACE] [log] [proto PROTOCOL] [from ADDRESS [port PORT] [to ADDRESS [port PORT] [comment COMMENT]
```

* `INTERFACE = eth0, eth1, ...`
* `PROTOCOL = udp, tcp, ...`
* `ADDRESS = 1.2.3.4 or 10.0.0.0/24`
* `PORT = 0-65535`
* `COMMENT = "comment"`


## Example

```yaml
services:
  firewall:
    image: dimajix/dcfw
    network_mode: host
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
      - dcfw.enabled=true
      - dcfw.input.default=deny
      - dcfw.input.rule.1=allow on eth0 proto tcp from 192.168.110.0/24 to any port 80
      - dcfw.input.rule.2=allow on eth0 proto tcp from 172.16.64.0/24 to any port 80
      - dcfw.output.default=deny
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
      - dcfw.enabled=true
      - dcfw.input.default=deny
      - dcfw.output.default=deny
      - dcfw.output.rule.1=allow proto tcp to 192.168.150.6 port 8080 comment "Allow communication to proxy"
      - dcfw.output.rule.3=allow proto tcp to 172.16.64.6 port 80 comment "Allow communication to web server"
    networks:
      firewall-bridge:
        ipv4_address: 172.16.64.7
```

## What are important limitations of DCFW?

* DCFW currently only supports IP addresses and IP networks in rules. You cannot specify DNS host namaes


## How can I contribute to DCFW?
