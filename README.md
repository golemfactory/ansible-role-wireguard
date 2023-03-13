# wireguard

This role creates a VPN using wireguard. It's designed to allow direct connection between nodes, not to tunnel whole internet access from one machine through other gateway.

Features:
  - A python script [gen_wireguard.py](gen_wireguard/gen_wireguard.py) is used to generate config for all hosts from a single-file network description. See: [rather complete example](gen_wireguard/tests/rather_complete_example/network.yml).
  - Nodes are connected P2P (with pre-shared key) or connection is routed through another node.
  - At least one of the nodes must have a public endpoint IP. PersistentKeepalive is added for peers without public endpoint IP.
  - Multiple interconnected subnets.
  - IPv4 and IPv6 private addresses (useful IPv6 private address range generator: [https://simpledns.plus/private-ipv6]).
  - Adds hostnames to `/etc/hosts`.


## Requirements

- Use `gen_wireguard.py` to create config files.
- It expects `wg-quick@` systemd service on nodes.


## Role Variables

- `wireguard_hostname`: (default: `"{{ inventory_hostname }}"`)
- `wireguard_interface`: (default: `wg0`)
- `wireguard_enable`: (default: `yes`)


## Dependencies

None


## Example Playbook

Before running the playbook, run:
```sh
./roles/wireguard/gen_wireguard/gen_wireguard.py -n wireguard_network.yml
```

Playbook:
```yml
- hosts: wireguard
  roles: [wireguard]
```


## License

[GPL-3.0-or-later](COPYING.txt)


## Author Information

Adam "etam" Mizerski <adam@mizerski.pl> https://etam-software.eu
