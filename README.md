# DCFW - The Docker Container Firewall

## What is DCFW?

## What Problem does DCFW solve?

## How can I use DCFW?

## What can I specify container rules?

allow|deny|reject [on INTERFACE]] [log] [proto PROTOCOL] [from ADDRESS [port PORT] [to ADDRESS [port PORT] [comment COMMENT]

INTERFACE = eth0, eth1, ...
PROTOCOL = udp, tcp, ...
ADDRESS = 1.2.3.4 or 10.0.0.0/24
PORT = 0-65535
COMMENT = "comment"


## What are important limitations of DCFW?

* DCFW currently only supports IP addresses and IP networks in rules. You cannot specify DNS host namaes


## How can I contribute to DCFW?
