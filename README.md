# DCFW - The Docker Container Firewall


## What is DCFW?

The Docker Container Firewall is a small Python application, which injects firewall rules into Docker containers.
It's the poor man's alternative to service meshes in Kubernetes clusters.


## What Problem does DCFW solve?

Some people like myself use Docker containers to publish some private services on the internet. Typical examples
are NextCloud, GitLab, project tracking software and more. Moreover, many people including myself do this from
their home using their private internet connection by opening a port on their internet router.

```text
  +--------------------------------------------------------------------+
  |    Private Home Network                                            |
  |                    +---------------------+                   +----------+
  |       +------------+    Network Switch   +-------------------+  Router  +------- Internet
  |       |            +----+--------------+-+                   +----------+
  |       |                 |              |                           |
  |  +----+----+   +--------+-+   +--------+----------------------+    |
  |  | Your PC |   | Your NAS |   |                               |    |
  |  +---------+   +----------+   |  +-----------+   +--------+   |    |
  |                               |  | NextCloud |   |  git   |   |    |
  |                               |  +-----------+   +--------+   |    |
  |                               |                               |    |
  |                               |           Docker Host         |    |
  |                               +-------------------------------+    |
  |                                                                    |
  +--------------------------------------------------------------------+
```
In itself, this works perfectly fine. But now, think about security implications of publishing services to the 
internet. Of course, you need to keep all services up to date to ensure that the latest security patches are applied. 
But assume that for whatever reason one of your Docker containers gets compromised by a bad actor.

Now the bad actor has access to the contents of your container. But he is also inside your network and might be able
to access additional services, like files stored on your NAS. He can freely move inside your network.

This is where a container firewall comes into play. Most people think firewalls are only used to control *inbound* 
traffic (i.e. they control which clients can connect to a server). But once a server is compromised, controlling the
*outbound* traffic of the server becomes at least as important. You want to ensure, that each service (or container
in the case of Docker) is only allowed to access other services that the container actually needs (for example, 
NextCloud might want to connect to a MariaDB server). All other outbound connections of the service should be blocked.
This serves as a second line of defense and prevents the bad actor who compromised the service to freely move inside
your network.

But how can you add a firewall to a Docker container? There are some solutions like ufw-Docker, but they have
their limitations. Specifically, they don't work if you use macvlan for Docker containers (as I do for some of them,
for good reasons). This is where DCFW comes into play, which enables you to add firewall rules directly to each
container, and they are implemented within each container.


## How is DCFW different from ufw-docker?

ufw-docker is a different solution which provides some firewall capabilities for Docker. The main difference is
that ufw-docker works on the Docker host itself and adds firewall rules, which then are evaluated for all traffic
on any network bridge used by Docker containers. This already provides a powerful solution, but it does not work
with Docker containers using a macvlan network.

In contrast to ufw-docker, DCFW applies iptable rules directly within each Docker container. This means that those
rules are in place independent of the network type being used. Moreover, DCFW uses labels on the Docker containers
themselves for defining the firewall rules - this simplifies the workflow, since the rules can be easily added
inside `docker-compose.yml` files (where they logically belong to) instead of being part of a global firewall rules
table on the Docker host.


## How does DCFW work?

DCFW scans the labels of all running Docker containers, and extract firewall rules from them. Then, DCFW applies
the firewall rules *inside the Docker container itself*. For the technical inclined people, dcfw enters the
network namespace (netns) of the container, and then applies iptable rules inside the container. In order to do so,
DCFW needs appropriate privileges (Linux capabilities). The container itself does not need (and even should not have)
these capabilities, otherwise a successful attacker could simply disable the firewall rules of the container.


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
    # Mark the Docker image as read-only to reduce attack surface
    read_only: true
    # Automatically restart firewall if it crashes
    restart: unless-stopped
    # Only keep capabilities that are really required
    cap_drop:
      - ALL
    cap_add:
      - CAP_NET_ADMIN
      - CAP_NET_BIND_SERVICE
      - CAP_SYS_ADMIN
      - CAP_KILL
      - CAP_CHOWN
      - CAP_SETGID
      - CAP_SETUID
      - CAP_DAC_OVERRIDE
    volumes:
      # Mount the Docker socket, such that DCFW notices when new containers are started
      - /var/run/docker.sock:/var/run/docker.sock:ro
      # Mount the Docker hosts /proc filesystem, which is required to enter the network namespace (netns) of other containers
      - /proc:/host/proc
      # Mount a tempfs file system to /var/run. Otherwise, the container file system cannot be read-only
      - type: tmpfs
        target: /var/run
    command:
      - --proc-dir=/host/proc
```

```yaml
services:
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

* DCFW currently only supports IP addresses and IP networks in rules. You cannot specify DNS host names.
* DCFW currently only supports IPv4


## How can I contribute to DCFW?
