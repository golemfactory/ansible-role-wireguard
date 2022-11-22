#!/usr/bin/python3

from pathlib import Path

import pytest
import yaml

from gen_wireguard import (
    build_etc_hosts,
    build_wg_quick_conf,
    parse_network_description,
    validate_network,
)


def run_directory_test(path: Path) -> None:
    with (path/"network.yml").open() as file:
        network = parse_network_description(yaml.safe_load(file))

    validate_network(network)

    with (path/"hosts.txt").open() as file:
        expected_hosts = file.read()
    assert build_etc_hosts(network) == expected_hosts

    for peer in network.peers.values():
        with (path/f"{peer.name}.txt").open() as file:
            expected_peer_config = file.read()
        assert build_wg_quick_conf(peer) == expected_peer_config


def test_just_ipv4() -> None:
    run_directory_test(Path("tests/just_ipv4"))


def test_just_ipv6() -> None:
    run_directory_test(Path("tests/just_ipv6"))


def test_rather_complete_example() -> None:
    run_directory_test(Path("tests/rather_complete_example"))


def run_should_fail_test(path: Path) -> None:
    with pytest.raises(AssertionError):
        with path.open() as file:
            network = parse_network_description(yaml.safe_load(file))
        validate_network(network)


def test_should_fail_disconnected_subnets() -> None:
    run_should_fail_test(Path("tests/should_fail_disconnected_subnets.yml"))


def test_should_fail_ipv4_ipv6() -> None:
    run_should_fail_test(Path("tests/should_fail_ipv4_ipv6.yml"))


def test_should_fail_missing_connection() -> None:
    run_should_fail_test(Path("tests/should_fail_missing_connection.yml"))


def test_should_fail_multiple_gateways() -> None:
    run_should_fail_test(Path("tests/should_fail_multiple_gateways.yml"))


def test_should_fail_num_clash() -> None:
    run_should_fail_test(Path("tests/should_fail_num_clash.yml"))


def test_should_fail_overlapping_subnets() -> None:
    run_should_fail_test(Path("tests/should_fail_overlapping_subnets.yml"))


def test_should_fail_peer_not_in_subnet() -> None:
    run_should_fail_test(Path("tests/should_fail_peer_not_in_subnet.yml"))
