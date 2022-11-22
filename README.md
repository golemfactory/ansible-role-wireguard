# ansible role for wireguard

Use [gen_wireguard.py](gen_wireguard/gen_wireguard.py) to generate config for all hosts from a single-file description.

Supports:
  - Multiple interconnected subnets
  - IPv4 and IPv6
  - P2P connections or routing through other nodes
  - Automatic PersistentKeepalive for peers without endpoint IP.

See: [rather complete example](gen_wireguard/tests/rather_complete_example/network.yml).

Useful IPv6 private address range generator: https://simpledns.plus/private-ipv6
