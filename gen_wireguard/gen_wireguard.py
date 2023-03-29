#!/usr/bin/python3

import argparse
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import (
    IPv4Address, IPv6Address,
    IPv4Network, IPv6Network,
)
import itertools
from pathlib import Path
import subprocess
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
)

import yaml


T = TypeVar('T')


def flatten(iterable: Iterable[List[T]]) -> List[T]:
    return sum(iterable, [])


def sorted_tuple(tup: Tuple[int, int]) -> Tuple[int, int]:
    return tup if tup[0] <= tup[1] else (tup[1], tup[0])


def all_or_none(iterable: Iterable[Any]) -> bool:
    # return True if either all elements are True or all are False
    all_ = True
    none = True
    for item in iterable:
        if bool(item):
            none = False
        else:
            all_ = False
    return all_ or none


def test_all_or_none() -> None:
    assert all_or_none([True, True, True])
    assert all_or_none([False, False, False])
    assert not all_or_none([True, False, True])


class Peer:
    def __init__(
            self,
            network: 'Network',
            name: str,
            interface_name: str,
            priv_key: str,
            pub_key: str,
            listen_port: int,
            hide_from_etc_hosts=False,
    ) -> None:
        self.network: Network = network
        self.subnets: Dict[Subnet, int] = {}
        self.endpoints: Dict[Subnet, str] = {}
        self.name = name
        self.interface_name = interface_name
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.listen_port = listen_port
        self.hide_from_etc_hosts = hide_from_etc_hosts
        network.add_peer(self)

    def indirect_subnets(self) -> Iterable['Subnet']:
        for subnet in self.network.subnets:
            if subnet in self.subnets:
                continue
            yield subnet

    def sorted_peers(self) -> Iterable[Tuple[int, 'Peer', 'Subnet']]:
        for subnet in self.subnets:
            my_num = subnet.get_peer_num(self)
            for peer_num in sorted(subnet.peers):
                if peer_num == my_num \
                       or sorted_tuple((my_num, peer_num)) in subnet.connections:
                    yield (peer_num, subnet.peers[peer_num], subnet)


def get_ipv4(subnet: IPv4Network, num: int) -> IPv4Address:
    return subnet.network_address + num


def get_ipv6(subnet: IPv6Network, num: int) -> IPv6Address:
    return subnet.network_address + num


IPvXNetwork = IPv4Network | IPv6Network
IPvXAddress = IPv4Address | IPv6Address


def get_ipvx(subnet: IPvXNetwork, num: int) -> IPvXAddress:
    return subnet.network_address + num


@dataclass
class Direct:
    psk: str


class Self:  # pylint: disable=too-few-public-methods
    pass


Connection = Direct | Peer | Self


class Subnet:
    def __init__(
            self,
            network: 'Network',
            ipv4_network: Optional[IPv4Network],
            ipv6_network: Optional[IPv6Network],
    ) -> None:
        self.network: Network = network
        self.ipv4_network = ipv4_network
        self.ipv6_network = ipv6_network
        self.peers: Dict[int, Peer] = {}
        self.connections: Dict[Tuple[int, int], Connection] = {}
        network.add_subnet(self)

    def __hash__(self) -> int:
        return hash((self.ipv4_network, self.ipv6_network))

    def __lt__(self, other: 'Subnet') -> bool:
        if self.ipv4_network is not None and other.ipv4_network is not None:
            return self.ipv4_network < other.ipv4_network
        if self.ipv6_network is not None and other.ipv6_network is not None:
            return self.ipv6_network < other.ipv6_network
        return self.ipv4_network is not None

    def overlaps(self, other: 'Subnet') -> bool:
        return (self.ipv4_network is not None and other.ipv4_network is not None
                and self.ipv4_network.overlaps(other.ipv4_network)) \
            or (self.ipv6_network is not None and other.ipv6_network is not None
                and self.ipv6_network.overlaps(other.ipv6_network))

    def add_peer(
            self,
            num: int,
            peer: Peer,
            endpoint_ip: Optional[str]
    ) -> None:
        assert peer.network == self.network
        assert num > 0
        assert self.ipv4_network is None \
            or num < (self.ipv4_network.num_addresses - 1)
        assert self.ipv6_network is None \
            or num < (self.ipv6_network.num_addresses - 1)
        assert num not in self.peers
        self.peers[num] = peer
        peer.subnets[self] = num
        self.connections[(num, num)] = Self()
        if endpoint_ip:
            peer.endpoints[self] = endpoint_ip

    def get_peer_num(self, peer: Peer) -> int:
        return peer.subnets[self]

    def add_connection(self, peer1: Peer, peer2: Peer,
                       conn: Connection) -> None:
        peer_num1 = self.get_peer_num(peer1)
        peer_num2 = self.get_peer_num(peer2)
        assert peer_num1 != peer_num2
        assert peer_num1 in self.peers
        assert peer_num2 in self.peers
        key = sorted_tuple((peer_num1, peer_num2))
        assert key not in self.connections
        self.connections[key] = conn

    def get_connection(self, peer1: Peer, peer2: Peer) -> Optional[Connection]:
        return self.connections.get(
            sorted_tuple((
                self.get_peer_num(peer1),
                self.get_peer_num(peer2)
            ))
        )

    def get_connections_of_peer(self, peer: Peer) -> Dict[int, Connection]:
        peer_num = self.get_peer_num(peer)
        result: Dict[int, Connection] = {}
        for (peer_num1, peer_num2), conn in self.connections.items():
            if peer_num1 == peer_num:
                result[peer_num2] = conn
            if peer_num2 == peer_num:
                result[peer_num1] = conn
        return result


class Network:
    def __init__(self) -> None:
        self.mtu: Optional[int] = None
        self.subnets: Set[Subnet] = set()
        self.peers: Dict[str, Peer] = {}

    def add_subnet(self, subnet: Subnet) -> None:
        assert subnet.network == self
        assert not subnet.peers
        assert not any(
            existing_subnet.overlaps(subnet)
            for existing_subnet in self.subnets)
        self.subnets.add(subnet)

    def add_peer(self, peer: Peer) -> None:
        assert peer.network == self
        assert peer.name not in self.peers
        self.peers[peer.name] = peer


def validate_network(network: Network, full: bool = True) -> None:
    # All peers belong to some subnets.
    for peer in network.peers.values():
        peer_subnets = set(peer.subnets.keys())
        assert peer_subnets
        assert peer_subnets.issubset(network.subnets)

    for subnet in network.subnets:
        # In a subnet all peers are connected to each other.
        if full:
            expected_connections = list(itertools.combinations_with_replacement(
                sorted(subnet.peers.keys()), 2))
            actual_connections = list(sorted(subnet.connections.keys()))
            assert expected_connections == actual_connections

        for peer1, peer2 in itertools.combinations(subnet.peers.values(), 2):
            connection = subnet.get_connection(peer1, peer2)
            if not full and connection is None:
                continue

            if subnet in peer1.endpoints and subnet in peer2.endpoints \
               and not isinstance(connection, Direct):
                print(f"Connection between {peer1.name} and {peer2.name} could be Direct")

            if subnet not in peer1.endpoints and subnet not in peer2.endpoints:
                assert isinstance(connection, Peer)

    # There is only 1 peer that is a gateway between adjacent subnets.
    # AND
    # Subnets are directly connected.
    # (this could be relaxed to "Subnets form a tree, not graph with loops.")
    for subnet1, subnet2 in itertools.combinations(network.subnets, 2):
        peers1 = set(subnet1.peers.values())
        peers2 = set(subnet2.peers.values())
        assert len(peers1.intersection(peers2)) == 1

    # All or none subnets have IPv4
    assert all_or_none(subnet.ipv4_network for subnet in network.subnets)
    # All or none subnets have IPv6
    assert all_or_none(subnet.ipv6_network for subnet in network.subnets)


def build_wg_quick_conf(me: Peer) -> str:
    addresses = [
        {
            ipvx: {
                "addr": get_ipvx(ipvx_network, num),
                "mask": ipvx_network.prefixlen,
            }
            for ipvx_network, ipvx
            in [
                (subnet.ipv4_network, "ipv4"),
                (subnet.ipv6_network, "ipv6"),
            ]
            if ipvx_network is not None
        }
        for subnet, num
        in sorted(me.subnets.items())
    ]

    config = "[Interface]\n"
    config += f"# {me.name}\n"
    config += "Address = " \
        + ", ".join(flatten(
            [
                f"{addr[ipvx]['addr']}/{addr[ipvx]['mask']}"
                for ipvx
                in ["ipv4", "ipv6"]
                if ipvx in addr
            ]
            for addr
            in addresses)) \
        + "\n"
    config += f"ListenPort = {me.listen_port}\n"
    config += f"PrivateKey = {me.priv_key}\n"
    config += f"# PublicKey = {me.pub_key}\n"
    for endpoint in sorted(me.endpoints.values()):
        config += f"# Endpoint = {endpoint}:{me.listen_port}\n"
    config += "Table = off\n"
    if me.network.mtu is not None:
        config += f"MTU = {me.network.mtu}\n"

    for subnet in me.indirect_subnets():
        for ipvx, ipvx_network in [
                ("ipv4", subnet.ipv4_network),
                ("ipv6", subnet.ipv6_network)
        ]:
            if ipvx_network is None:
                continue
            route = (
                f"{ipvx_network} "
                f"dev {me.interface_name} "
                f"src {addresses[0][ipvx]['addr']}"
            )
            config += f"PostUp = ip r add {route}\n"
            config += f"PreDown = ip r del {route}\n"

    connections_via_peer: Dict[Peer, Set[int]] = defaultdict(set)
    for subnet in me.subnets:
        for target_peer_num, connection_via_peer in subnet.get_connections_of_peer(me).items():
            if not isinstance(connection_via_peer, Peer):
                continue
            connections_via_peer[connection_via_peer].add(target_peer_num)

    for peer_num, peer, peer_subnet in me.sorted_peers():
        config += "\n"

        peer_ipv4 = get_ipv4(peer_subnet.ipv4_network, peer_num) \
            if peer_subnet.ipv4_network else None
        peer_ipv6 = get_ipv6(peer_subnet.ipv6_network, peer_num) \
            if peer_subnet.ipv6_network else None

        if peer == me:
            config += f"# {me.name} {peer_ipv4 or peer_ipv6} it's me\n"
            continue

        connection = peer_subnet.get_connection(me, peer)
        assert connection is not None  # guaranteed by sorted_peers
        assert not isinstance(connection, Self)  # guaranteed by "if peer == me: continue"
        if isinstance(connection, Peer):
            config += f"# {peer.name} {peer_ipv4} via {connection.name}\n"
            continue

        config += "[Peer]\n"
        config += f"# {peer.name}\n"
        config += f"PublicKey = {peer.pub_key}\n"

        if peer_subnet in peer.endpoints:
            config += f"Endpoint = {peer.endpoints[peer_subnet]}:{peer.listen_port}\n"

        config += f"PresharedKey = {connection.psk}\n"

        allowed_ips = []
        if peer_ipv4 is not None:
            allowed_ips.append(f"{peer_ipv4}/32")
        if peer_ipv6 is not None:
            allowed_ips.append(f"{peer_ipv6}/128")
        for proxy_target_num in connections_via_peer[peer]:
            if peer_subnet.ipv4_network is not None:
                allowed_ips.append(f"{get_ipv4(peer_subnet.ipv4_network, proxy_target_num)}/32")
            if peer_subnet.ipv6_network is not None:
                allowed_ips.append(f"{get_ipv6(peer_subnet.ipv6_network, proxy_target_num)}/128")
        for other_peer_subnet in peer.subnets:
            if other_peer_subnet == peer_subnet:
                continue
            if other_peer_subnet.ipv4_network is not None:
                allowed_ips.append(str(other_peer_subnet.ipv4_network))
            if other_peer_subnet.ipv6_network is not None:
                allowed_ips.append(str(other_peer_subnet.ipv6_network))
        config += "AllowedIPs = " + ", ".join(allowed_ips) + "\n"

        if not me.endpoints or peer_subnet not in peer.endpoints:
            config += "PersistentKeepalive = 60\n"

    return config


def build_etc_hosts(network: Network) -> str:
    ipv4_hosts = []
    ipv6_hosts = []
    for subnet, num in sorted(sorted(peer.subnets.items())[0] for peer in network.peers.values()):
        peer = subnet.peers[num]
        if peer.hide_from_etc_hosts:
            continue
        if subnet.ipv4_network is not None:
            ipv4 = get_ipv4(subnet.ipv4_network, num)
            ipv4_hosts.append(f"{ipv4} {peer.name}")
        if subnet.ipv6_network is not None:
            ipv6 = get_ipv6(subnet.ipv6_network, num)
            ipv6_hosts.append(f"{ipv6} {peer.name}")
    return "\n".join(ipv4_hosts + ipv6_hosts + [""])


def get_public_key(private_key: str) -> str:
    return subprocess.run(
        ["wg", "pubkey"],
        input=private_key,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.rstrip()


def test_get_public_key() -> None:
    assert get_public_key("WGo1JRIe0pKUG+NnlBZf3BiV4M/5k8NQtgynH5vS43Q=") \
        == "RcqqsPIekbbhQRQsQmmXzgsGchZtnobmAeMnfFRC+VA="


def parse_network_description(data: Any) -> Network:
    network = Network()

    if "mtu" in data:
        network.mtu = int(data["mtu"])

    for peer_name, peer_config in data["peers"].items():
        Peer(
            network,
            peer_name,
            peer_config.get("interface", "wg0"),
            peer_config["private_key"],
            get_public_key(peer_config["private_key"]),
            peer_config["listen_port"],
            peer_config.get("hide_from_etc_hosts", False),
        )

    for subnet_config in data["subnets"]:
        subnet = Subnet(
            network,
            IPv4Network(subnet_config["ipv4_network"]) if "ipv4_network" in subnet_config else None,
            IPv6Network(subnet_config["ipv6_network"]) if "ipv6_network" in subnet_config else None,
        )

        for peer_name, subnet_peer_config in subnet_config["peers"].items():
            subnet.add_peer(
                subnet_peer_config["num"],
                network.peers[peer_name],
                subnet_peer_config.get("endpoint_ip")
            )

        for conn_peer_name1, conn_peers in subnet_config["connections"].items():
            for conn_peer_name2, conn_config in conn_peers.items():
                assert ("psk" in conn_config) ^ ("via" in conn_config)
                subnet.add_connection(
                    network.peers[conn_peer_name1],
                    network.peers[conn_peer_name2],
                    Direct(conn_config["psk"])
                    if "psk" in conn_config
                    else network.peers[conn_config["via"]]
                )

    return network


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-n', '--network',
        required=True,
        type=Path,
    )
    parser.add_argument(
        '-o', '--output-dir',
        type=Path,
        default=Path("wireguard_conf"),
    )
    parser.add_argument(
        '--full',
        action=argparse.BooleanOptionalAction,
        help="validate that all nodes are connected to eachother",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    with open(args.network, encoding="utf-8") as file:
        network_description = yaml.safe_load(file)

    network = parse_network_description(network_description)
    validate_network(network, args.full)

    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    with open(args.output_dir/"etc_hosts.txt", 'w', encoding="utf-8") as file:
        file.write(build_etc_hosts(network))

    for peer_name, peer in network.peers.items():
        peer_dir = args.output_dir/f"{peer_name}"
        peer_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(peer_dir/f"{peer.interface_name}.conf", 'w', encoding="utf-8") as file:
            file.write(build_wg_quick_conf(peer))


if __name__ == "__main__":
    main()
