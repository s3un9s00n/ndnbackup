# CALab-NDN-Dev

### Cryptography Application Lab.
[Named-Data] - Official NDN  
[Named-Data-GitHub] - Official NDN GitHub Repository

----

## Server Environment
| Type | Server Info | IP Addr | Environment | README |
|:-----|:--------------------------|:-----|:------------|:------------:|  
| Consumer | ndn-consrouter:ndn | 192.168.0.106 | Ubuntu 20.04.3 LTS, Docker version 20.10.12, build e91ed57 | [src/ndn_dev-ConsumerA][Consumer-A] [src/ndn_dev-ConsumerB][Consumer-B] |
| Router | ndn-router1:router | 192.168.0.99 | Ubuntu 20.04.3 LTS | [src/ndn_dev-router][router] |
| Router | ndn-router2:router | 192.168.0.100 | Ubuntu 20.04.3 LTS | [src/ndn_dev-router][router] |
| Router | ndn-router3:router | 192.168.0.101 | Ubuntu 20.04.3 LTS | [src/ndn_dev-router][router] |
| Producer | ndn-producer:producer | 192.168.0.104 | Ubuntu 20.04.3 LTS, Docker version 20.10.12, build e91ed57 | [src/ndn_dev-ProducerC][Producer-C] [src/ndn_dev-ProducerD][Producer-D] |

----

## Features
- Format-Preserving Encryption [FF3-1]
- Developments Security Solutions for NDN 
- Router Forwarding Solutions
- ETC... (plz.. add)

----

## Specification 
- [NDN-GitHub-ndn-cxx]
- [NDN-GitHub-NFD]
- [NDN-GitHub-ndn-tools]

### Consumer
- N/A
### Producer
- N/A
### Router
- [NDN-GitHub-ndn-traffic-generator]
- [NDN-GitHub-PSync]

----



[Consumer-A]: <https://github.com/isanghyeon/calab-ndn-dev/tree/main/src/ndn_dev-consumerA/README.md>
[Consumer-B]: <https://github.com/isanghyeon/calab-ndn-dev/tree/main/src/ndn_dev-consumerB/README.md>
[router]: <https://github.com/isanghyeon/calab-ndn-dev/tree/main/src/ndn_dev-router/README.md>
[Producer-C]: <https://github.com/isanghyeon/calab-ndn-dev/tree/main/src/ndn_dev-producerC/README.md>
[Producer-D]: <https://github.com/isanghyeon/calab-ndn-dev/tree/main/src/ndn_dev-producerD/README.md>

[Named-Data]: <https://named-data.net/>
[Named-Data-GitHub]: <https://github.com/named-data>

[NDN-GitHub-ndn-cxx]: <https://github.com/named-data/ndn-cxx>
[NDN-GitHub-NFD]: <https://github.com/named-data/NFD>
[NDN-GitHub-ndn-tools]: <https://github.com/named-data/ndn-tools>
[NDN-GitHub-ndn-traffic-generator]: <https://github.com/named-data/ndn-traffic-generator>
[NDN-GitHub-NLSR]: <https://github.com/named-data/NLSR>
[NDN-GitHub-PSync]: <https://github.com/named-data/PSync>