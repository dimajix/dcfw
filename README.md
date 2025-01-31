# DCFW - The Docker Container Firewall

[![GitHub Repo stars](https://img.shields.io/github/stars/dimajix/dcfw)](https://github.com/dimajix/dcfw)
[![Docker Pulls](https://img.shields.io/docker/pulls/dimajix/dcfw)](https://hub.docker.com/r/dimajix/dcfw)
![GitHub License](https://img.shields.io/github/license/dimajix/dcfw)

## 💡 What is DCFW?

The Docker Container Firewall is a small Python application, which injects firewall rules into Docker containers.
It's the poor man's alternative to service meshes in Kubernetes clusters.


## 🤔 What problem does DCFW solve?

Some people like myself use Docker containers to publish some private services on the internet. Typical examples
are NextCloud, GitLab, project tracking software and more. Moreover, many people including myself do this from
their home using their private internet connection by opening a port on their internet router.

```text
  +--------------------------------------------------------------------------------+
  |    Your Private Home Network                                                   |
  |                    +---------------------+                               +----------+
  |       +------------+    Network Switch   +-------------------------------+  Router  +------- Internet
  |       |            +----+--------------+-+                               +----------+
  |       |                 |              |                                       |
  |  +----+----+   +--------+-+   +--------+----------------------------------+    |
  |  | Your PC |   | Your NAS |   |        Public Services                    |    |
  |  +---------+   +----------+   |  +-----------+   +--------+   +--------+  |    |
  |                               |  | NextCloud |   |  git   |   |  dcfw  |  |    |
  |                               |  +-----------+   +--------+   +--------+  |    |
  |                               |                                           |    |
  |                               |               Your Docker Host            |    |
  |                               +-------------------------------------------+    |
  |                                                                                |
  +--------------------------------------------------------------------------------+
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

Essentially, I recommend using firewalls blocking outbound traffic to limit the blast radius in case a service
is compromised by an attacker. A firewall will not prevent the intrusion in the first place (this needs to be prevented
by other measures), but it can limit the possible harm.

But how can you add a firewall to a Docker container? There are some solutions like ufw-Docker, but they have
their limitations. Specifically, they don't work if you use macvlan for Docker containers (as I do for some of them,
for good reasons). This is where DCFW comes into play, which enables you to add firewall rules directly to each
container, and they are implemented within each container.


## 🐶🐱 How is DCFW different from ufw-docker?

ufw-docker is a different solution which provides some firewall capabilities for Docker. The main difference is
that ufw-docker works on the Docker host itself and adds firewall rules, which then are evaluated for all traffic
on any network bridge used by Docker containers. This already provides a powerful solution, but it does not work
with Docker containers using a macvlan network.

In contrast to ufw-docker, DCFW applies iptable rules directly within each Docker container. This means that those
rules are in place independent of the network type being used. Moreover, DCFW uses labels on the Docker containers
themselves for defining the firewall rules - this simplifies the workflow, since the rules can be easily added
inside `docker-compose.yml` files (where they logically belong to) instead of being part of a global firewall rules
table on the Docker host.


## 🤓 How does DCFW work?

DCFW scans the labels of all running Docker containers, and extract firewall rules from them. Then, DCFW applies
the firewall rules *inside the Docker container itself*. For the technical inclined people, dcfw enters the
network namespace (netns) of the container, and then applies iptable rules inside the container. In order to do so,
DCFW needs appropriate privileges (Linux capabilities). The container itself does not need (and even should not have)
these capabilities, otherwise a successful attacker could simply disable the firewall rules of the container.


## 🚀 How can I use DCFW?

DCFW is designed to be simple to use. Basically, you need to run DCFW inside a Docker container and add labels
to all Docker containers which should be protected by DCFW.

### ⏩ 1. Start DCFW inside a Docker container

You can start DCFW inside a Docker container. Since DCFW needs to access the network namespace of other containers,
it needs to have access to the `/proc` directory of the Docker host. Moreover, DCFW also needs several privileges
in form of Linux capabilities. Finally, DCFW also needs access to the Docker socket to retrieve information about
running containers.

In order to satisfy all these little requirements, the simplest thing is to create a `docker-compose.yml` file as 
follows:

```yaml
services:
  dcfw:
    image: dimajix/dcfw
    container_name: dcfw
    # Mark the Docker image as read-only to reduce attack surface
    read_only: true
    # Automatically restart firewall if it crashes
    restart: unless-stopped
    # DCFW needs to see all processes from all other Docker containers. Therefore, use the hosts PID namespace
    pid: host 
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
    # We don't need any network
    network_mode: none
    volumes:
      # Mount the Docker socket, such that DCFW notices when new containers are started
      - /var/run/docker.sock:/var/run/docker.sock:ro
      # Mount a tempfs file system to /var/run. Otherwise, the container file system cannot be read-only
      - type: tmpfs
        target: /var/run
```


### 🏷️ 2. Add `dcfw.*` labels to Docker containers

In order to enable the firewall for a specific Docker container, you need to add some labels:
* `dcfw.enable: [true|false]` enables or disables DCFW for this container. If there is no label `dcfw.enable`, then 
* DCFW will not touch the container.
* `dcfw.input.policy: [allow|deny]` sets the default policy for incoming traffic (i.e. communication which
enters the container service from some client).
* `dcfw.output.policy: [allow|deny]` sets the default policy for outgoing traffic (i.e. communication which
leaves the container to access services outside the container).
* `dcfw.input.rule.[nnn]: <rule>` defines one rule for incoming traffic. `nnn` is an integer number. Rules will be 
applied in ascending order of these numbers (i.e. `dcfw.input.rule.23` will be applied before `dcfw.input.rule.87`)
* `dcfw.output.rule.[nnn]: <rule>` defines one rule for outgoing traffic. `nnn` is an integer number. Rules will be 
applied in ascending order of these numbers (i.e. `dcfw.input.rule.23` will be applied before `dcfw.input.rule.87`)

Each rule has the following syntax:
```text
allow|deny|reject [log] [on INTERFACE] [proto PROTOCOL] [from ADDRESS [port PORT]] [to ADDRESS [port PORT]] [comment COMMENT]
```
with the following parameters:
* `allow|deny|reject` defines the type of the rule. `allow` lets traffic pass, `deny` silently blocks (drops) the 
traffic, `reject` will reject the traffic (i.e. the other side will be informed)
* If the keyword `log` is specified, each match of the rule will be logged.
* You can optionally specify a network interface via `on`. The `INTERFACE` typically is `eth0`, `eth1` etc. Note that
the interface refers to its name *inside* the Docker container.
* You can optionally specify a `protocol`. The `PROTOCOL` typically is `udp`, `tcp`, `igmp` etc.
* The optional `from` part specifies the origin of the traffic. For on `dcfw.input.rule`, this refers to some client
trying to access the service. The `ADDRESS` either is a single IP address (like `1.2.3.4`), an IP network (like
`192.168.110.0/24`) or `any` (for any host, which is equivalent to `0.0.0.0/0`). You can also optionally specify
a source `port` number. Port numbers also need a protocol, otherwise they don't have any effect.
* The optional `to` part specifies the target of the traffic. For on `dcfw.output.rule`, this refers to some external
service the container tries to access. The `ADDRESS` either is a single IP address (like `1.2.3.4`), an IP network 
(like `192.168.110.0/24`) or `any` (for any host, which is equivalent to `0.0.0.0/0`). You can also optionally specify
a source `port` number. Port numbers also need a protocol, otherwise they don't have any effect.
* Finally, you can also specify a `comment`. The `COMMENT` is an arbitrary quoted string, which is simply attached
to the iptables rules. It only has informational character and does not otherwise change the behaviour.

### 👉 Example
An example for a web server might look as follows:
```yaml
services:
  webserver:
    # Pick a simple and small web server Docker image
    image: httpd:2.2-alpine
    labels:
      # Enable DCFW for this container
      dcfw.enable: true
      # Default policy is to deny all incoming traffic
      dcfw.input.policy: deny
      # Allow Access to port 80 from the network 192.168.110.0/24
      dcfw.input.rule.1: allow on eth0 proto tcp from 192.168.110.0/24 to any port 80
      # Allow Access to port 80 from the network 172.16.64.0/24
      dcfw.input.rule.2: allow on eth0 proto tcp from 172.16.64.0/24 to any port 80
      # Default policy is to block all outgoing traffic (this probably is the more interesting part limiting the
      # blast radius in case this container is compromised)
      dcfw.output.policy: deny
      # Allow access to some MariaDB / MySQL server on 192.168.150.6
      dcfw.output.rule.1: allow proto tcp to 192.168.150.6 port 3306 comment "Allow access to MariaDB"
```

Actually, I highly recommend to apply some additional best practices to containers:
* Try to mark the container as `read_only`, this prevents tampering with the filesystem inside the container.
Unfortunately, not all Docker images support this very well.
* Drop all privileges (Linux capabilities), and only add those which are strictly required by the container.
* Explicitly provide static IP addresses. This might get important once you use DCFW to narrow down traffic
between several containers.

```yaml
services:
  webserver:
    image: httpd:2.2-alpine
    container_name: some-webserver
    # Mark container filesystem as read-only 
    read_only: true
    # Drop all privileges / Linux capabilities
    cap_drop:
      - ALL
    # Add only those capabilities, which are really required
    cap_add:
      - CAP_CHOWN
      - CAP_SETGID
      - CAP_SETUID
      - CAP_KILL
    # Add DCFW labels
    labels:
      - dcfw.enable=true
      - dcfw.input.policy=deny
      - dcfw.input.rule.1=allow on eth0 proto tcp from 192.168.110.0/24 to any port 80
      - dcfw.input.rule.2=allow on eth0 proto tcp from 172.16.64.0/24 to any port 80
      - dcfw.output.policy=deny
      - dcfw.output.rule.1=allow proto tcp to 192.168.150.6 port 8080 comment "Allow communication to proxy"
    # Mount temporary directory for the logs - otherwise the webserver won't start in read_only mode
    volumes:
      - type: tmpfs
        target: /usr/local/apache2/logs
    networks:
      dcfw-bridge:
        # Explicitly provide static IP address
        ipv4_address: 172.16.64.6

networks:
  dcfw-bridge:
    name: dcfw-bridge
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.64.0/24
          ip_range: 172.16.64.0/24
          gateway: 172.16.64.1
```

## 🚧 What are important limitations of DCFW?

* DCFW currently only supports IP addresses and IP networks in rules. Unfortunately, you cannot use DNS host names in
rules. Therefore, you should use static IP addresses whenever possible. 
* DCFW currently only supports IPv4.


## 👆 FAQ

### I don't see any logging!
DCFW will log all packets blocked by the default input and output policy. Additionally, DCFW will also log all packets
matching a rule with the `log` option. Now the question is, where do we see those logs? Since the logging is actually
done by the kernel, you should find the log lines in the Linux kernel log of the Docker host (not the Docker container).
So you should see the output via the following command
```shell
sudo journalctl --all -f
```

But even the that doesn't work out of the box, since per default Linux will only log iptables rules of the host itself,
not iptables rules of any container (Docker, lxc, lxd, ...). But you can instruct the Linux kernel to also log
iptables rules of all containers (actually of all network namespaces) via the following command:
```shell
sudo sysctl net.netfilter.nf_log_all_netns=1      
```

## 📜 License

This project is licensed under GNU General Public License 3.0 - see the [COPYING](COPYING) file for details.
