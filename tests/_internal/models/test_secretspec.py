"""Tests for SecretSpec"""

import pytest
from mock import patch

from docker.client import DockerClient
from docker.models.services import ServiceCollection
from docker.models.secrets import SecretCollection
from docker.types.services import SecretReference

from certbot_docker_swarm._internal.models.secretspec import SecretSpec

from tests._internal.fakes.docker import *

class TestSecretSpec:
    @pytest.fixture
    def docker_client(self):
        return DockerClient()

    @pytest.mark.dependency()
    def test_init_no_spec(self, docker_client):
        with patch.object(SecretSpec, "from_swarm") as mock_from_env:
            s = SecretSpec(docker_client, spec=None)
            mock_from_env.assert_called_once()

    @pytest.mark.dependency()
    def test_init_with_spec(self, docker_client):
        s = SecretSpec(docker_client, spec={})
        assert s.spec == {}

    @pytest.mark.dependency(depends=["TestSecretSpec::test_init_with_spec"])
    def test_services(self, docker_client):
        s = SecretSpec(docker_client, spec={})
        assert s.services == {}

    @pytest.mark.dependency(depends=["TestSecretSpec::test_init_no_spec"])
    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    def test_from_swarm(self, docker_client):
        s = SecretSpec(docker_client, spec=None)
        assert "qwerty" in s.services

        secret_ids = set([x.get("SecretID") for x in s.get_refs("qwerty")])
        assert secret_ids == set(["c", "d"])

    @pytest.mark.dependency(depends=[
        "TestSecretSpec::test_init_with_spec",
        "TestSecretSpec::test_services"
    ])
    def test_set_ref(self, docker_client):
        ref = SecretReference("a", "a_name", "a_file", "0", "0", "292")

        s = SecretSpec(docker_client, spec={})
        s.set_ref("abcd", ref)

        assert len(s.services) == 1
        assert s.services.get("abcd")["a"] == ref

    @pytest.mark.dependency(depends=[
        "TestSecretSpec::test_init_with_spec",
        "TestSecretSpec::test_set_ref"
    ])
    def test_get_refs(self, docker_client):
        ref = SecretReference("a", "a_name", "a_file", "0", "0", "292")

        s = SecretSpec(docker_client, spec={})
        s.set_ref("abcd", ref)

        assert s.get_refs("abcd") == [ref]

    @pytest.mark.dependency(depends=[
        "TestSecretSpec::test_init_no_spec",
        "TestSecretSpec::test_services",
        "TestSecretSpec::test_get_refs"
    ])
    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    @patch.object(ServiceCollection, "get", ServiceCollectionDefs.get)
    @patch.object(SecretCollection, "get", SecretCollectionDefs.get)
    def test_update_refs(self, docker_client):
        # The fake service "qwerty" has Secrets "c" and "d". Let's use "c".
        s = SecretSpec(docker_client, spec=None)

        # Secret "e" renews "c".
        e = SecretCollectionDefs.get("e")
        assert e is not None
        s.update_refs(e)
        refs = set([x.get("SecretID") for x in s.get_refs("qwerty")])
        assert refs == set(["e", "d"])

        # The fake service "qwerty" has Secrets "c" and "d". Let's use "c".
        s = SecretSpec(docker_client, spec=None)

        # Secret "a" doesn't renew "c".
        a = SecretCollectionDefs.get("a")
        assert a is not None
        s.update_refs(a)
        refs = set([x.get("SecretID") for x in s.get_refs("qwerty")])
        assert refs == set(["c", "d"])

    @pytest.mark.dependency(depends=[
        "TestSecretSpec::test_init_no_spec",
        "TestSecretSpec::test_services",
    ])
    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    @patch.object(SecretCollection, "get", SecretCollectionDefs.get)
    def test_get_updated_ref(self, docker_client):
        # The fake service "qwerty" has Secrets "c" and "d". Let's use "c".
        s = SecretSpec(docker_client, spec=None)
        ref = s.services.get("qwerty").get("c")

        # Secret "e" renews "c".
        e = SecretCollectionDefs.get("e")
        assert e is not None
        new_ref = s.get_updated_ref(ref, e)
        assert new_ref.get("SecretID") == "e"

        # Secret "a" doesn't renew "c".
        a = SecretCollectionDefs.get("a")
        assert a is not None
        new_ref = s.get_updated_ref(ref, a)
        assert new_ref.get("SecretID") == "c"

    def test_write(self):
        pass

    def test_read(self):
        pass
