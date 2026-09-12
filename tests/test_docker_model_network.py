from hashlib import sha256

import pytest

from llm_redteam.docker_model_network import (
    DockerContainerNetworkMembershipInspection,
    DockerIsolatedModelNetworkProfile,
    DockerModelNetworkInspection,
    attest_isolated_model_network,
)


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _profile() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _network_payload(
    profile: DockerIsolatedModelNetworkProfile,
    *,
    internal: bool = True,
    gateway_mode_ipv4: str = "isolated",
    enable_ipv6: bool = False,
    model_name: str = "model-peer",
    extra_member: bool = False,
) -> dict[str, object]:
    containers: dict[str, object] = {
        "a" * 64: {
            "Name": "agent-peer",
            "IPv4Address": "172.31.0.2/24",
            "IPv6Address": "",
        },
        "b" * 64: {
            "Name": model_name,
            "IPv4Address": "172.31.0.3/24",
            "IPv6Address": "",
        },
    }
    if extra_member:
        containers["c" * 64] = {
            "Name": "unexpected-peer",
            "IPv4Address": "172.31.0.4/24",
            "IPv6Address": "",
        }
    return {
        "Id": "d" * 64,
        "Name": "rt-model-net",
        "Driver": "bridge",
        "Scope": "local",
        "Internal": internal,
        "Ingress": False,
        "EnableIPv6": enable_ipv6,
        "Options": {
            "com.docker.network.bridge.gateway_mode_ipv4": gateway_mode_ipv4,
        },
        "Labels": {
            "llm-redteam.model-network-profile-sha256": profile.profile_sha256,
        },
        "Containers": containers,
    }


def _container_payload(
    container_id: str,
    name: str,
    *,
    running: bool = True,
    network_ids: tuple[str, ...] = ("d" * 64,),
) -> dict[str, object]:
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "State": {"Running": running},
        "NetworkSettings": {
            "Networks": {
                f"net-{index}": {"NetworkID": network_id}
                for index, network_id in enumerate(network_ids)
            }
        },
    }


def _attest(
    *,
    profile: DockerIsolatedModelNetworkProfile | None = None,
    network_payload: dict[str, object] | None = None,
    agent_network_ids: tuple[str, ...] = ("d" * 64,),
    model_network_ids: tuple[str, ...] = ("d" * 64,),
    model_running: bool = True,
):
    profile = profile or _profile()
    inspection = DockerModelNetworkInspection.from_docker_network_inspect(
        network_payload or _network_payload(profile)
    )
    agent = DockerContainerNetworkMembershipInspection.from_docker_inspect(
        _container_payload(
            "a" * 64,
            "agent-peer",
            network_ids=agent_network_ids,
        )
    )
    model = DockerContainerNetworkMembershipInspection.from_docker_inspect(
        _container_payload(
            "b" * 64,
            "model-peer",
            running=model_running,
            network_ids=model_network_ids,
        )
    )
    return attest_isolated_model_network(
        profile=profile,
        inspection=inspection,
        agent_membership=agent,
        model_membership=model,
        network_name="rt-model-net",
        agent_container_id_sha256=_digest("a" * 64),
        model_peer_container_id_sha256=_digest("b" * 64),
    )


def test_network_create_command_is_internal_and_gateway_isolated() -> None:
    profile = _profile()

    command = profile.docker_network_create_command(network_name="rt-model-net")

    assert command[:4] == ("docker", "network", "create", "--driver")
    assert "--internal" in command
    assert "com.docker.network.bridge.gateway_mode_ipv4=isolated" in command
    assert (
        f"llm-redteam.model-network-profile-sha256={profile.profile_sha256}"
        in command
    )
    assert command[-1] == "rt-model-net"


def test_exact_two_peer_single_network_attestation_succeeds() -> None:
    profile = _profile()

    attestation = _attest(profile=profile)

    assert attestation.network_profile_sha256 == profile.profile_sha256
    assert attestation.agent_container_id_sha256 == _digest("a" * 64)
    assert attestation.model_peer_container_id_sha256 == _digest("b" * 64)
    assert attestation.model_endpoint_origin_sha256 == _digest(
        "http://model-peer:11434"
    )
    assert len(attestation.attestation_sha256) == 64


@pytest.mark.parametrize(
    ("payload_update", "failure"),
    [
        ({"Internal": False}, "internal"),
        (
            {
                "Options": {
                    "com.docker.network.bridge.gateway_mode_ipv4": "nat",
                }
            },
            "gateway_mode_ipv4",
        ),
        ({"EnableIPv6": True}, "ipv6_enabled"),
    ],
)
def test_network_security_invariants_fail_closed(
    payload_update: dict[str, object],
    failure: str,
) -> None:
    profile = _profile()
    payload = _network_payload(profile)
    payload.update(payload_update)

    with pytest.raises(ValueError, match=failure):
        _attest(profile=profile, network_payload=payload)


def test_unexpected_third_network_peer_fails_closed() -> None:
    profile = _profile()
    payload = _network_payload(profile, extra_member=True)

    with pytest.raises(ValueError, match="exact_member_set"):
        _attest(profile=profile, network_payload=payload)


@pytest.mark.parametrize("peer", ["agent", "model"])
def test_dual_homed_peer_fails_closed(peer: str) -> None:
    second_network = "e" * 64
    kwargs: dict[str, object] = {}
    if peer == "agent":
        kwargs["agent_network_ids"] = ("d" * 64, second_network)
    else:
        kwargs["model_network_ids"] = ("d" * 64, second_network)

    with pytest.raises(ValueError, match=f"{peer}_single_network"):
        _attest(**kwargs)


def test_model_peer_name_must_bind_declared_endpoint_host() -> None:
    profile = _profile()
    payload = _network_payload(profile, model_name="other-model")

    with pytest.raises(ValueError, match="model_peer_network_name"):
        _attest(profile=profile, network_payload=payload)


def test_stopped_model_peer_fails_closed() -> None:
    with pytest.raises(ValueError, match="model_running"):
        _attest(model_running=False)


def test_network_policy_fingerprint_binds_model_endpoint() -> None:
    base = _profile()
    changed_port = DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11435,
    )
    changed_host = DockerIsolatedModelNetworkProfile(
        model_endpoint_host="alternate-model",
        model_endpoint_port=11434,
    )

    assert base.profile_sha256 != changed_port.profile_sha256
    assert base.profile_sha256 != changed_host.profile_sha256


def test_missing_profile_label_cannot_be_attested() -> None:
    profile = _profile()
    payload = _network_payload(profile)
    payload["Labels"] = {}

    with pytest.raises(ValueError, match="profile_label"):
        _attest(profile=profile, network_payload=payload)
