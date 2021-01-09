"""Tests for SwarmInstaller."""

import os
import time
import pytest
from mock import patch, MagicMock

from certbot.errors import PluginError
from docker.client import DockerClient
from docker.models.nodes import Node, NodeCollection
from docker.models.secrets import Secret, SecretCollection

from certbot_docker_swarm._internal.installer import SwarmInstaller
from certbot_docker_swarm._internal.installer import SwarmInstallerUtils

class NodeCollectionMock:
    @classmethod
    def list(cls):
        return [
            Node(attrs={
                "ID": "abcde",
                "Spec": {
                    "Role": "manager"
                }
            })
        ]

    @classmethod
    def get(cls, node_id):
        for n in cls.list():
            if n.id == node_id:
                return n

    @classmethod
    def get_not_manager(cls, node_id):
        tmp = cls.get(node_id)
        tmp.attrs["Spec"]["Role"] = "node"
        return tmp

class SecretCollectionMock:
    @classmethod
    def list(cls):
        ret = []

        return [
            Secret(attrs={
                'ID': 'a',
                'Spec': {
                    'Name': 'example.com_cert_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '1.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'cert',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'b',
                'Spec': {
                    'Name': 'example.com_chain_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '1.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'chain',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'c',
                'Spec': {
                    'Name': 'example.com_cert_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'cert',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'd',
                'Spec': {
                    'Name': 'example.com_chain_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'chain',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'e',
                'Spec': {
                    'Name': 'example.com_cert_v1',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'cert',
                        'certbot.version': '1'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'f',
                'Spec': {
                    'Name': 'example.com_chain_v1',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'chain',
                        'certbot.version': '1'
                    }
                }
            })
        ]

    @classmethod
    def get(cls, secret_id):
        for s in cls.list():
            if s.id == secret_id:
                return s

    @classmethod
    def get_predefined(cls, _secret_id, _name, _labels):
        """Return a mocked method that always returns a predefined Secret.

        :param str _secret_id: The predefined Secret ID.
        :param str _name: The predefined Secret name
        :param str _labels: The predefined Secret labels.

        :return: The method described above.
        :rtype: function
        """
        def closure(cls, secret_id):
            return Secret({
                "ID": _secret_id,
                "Spec": {
                    "Name": _name,
                    "Labels": _labels
                }
            })

        return closure

    @classmethod
    def create_predefined(cls, _secret_id, _name, _labels):
        """Return a mocked method that asserts it's called with correct args.

        :param str _secret_id: The predefined ID of the Secret that's created.
        :param str _name: The expected Secret name.
        :param str _labels: The expected labels.

        :return: The method described above.
        :rtype: function
        """
        def closure(cls, name, data, labels):
            assert _name == name
            assert _labels == labels
            return Secret({"ID": _secret_id})

        return closure

class DockerClientMock:
    @classmethod
    def info(cls, *args, **kwargs):
        return {
            "Swarm": {
                "NodeID": "abcde",
                "LocalNodeState": "active",
                "Cluster": {
                    "Spec": {
                        "Orchestration": {
                            "TaskHistoryRetentionLimit": 5
                        }
                    }
                }
            }
        }

    @classmethod
    def info_not_swarm(cls, *args, **kwargs):
        tmp = cls.info()
        tmp["Swarm"]["LocalNodeState"] = "inactive"
        return tmp

class TestSwarmInstaller:
    @pytest.fixture
    def docker_client(self):
        return DockerClient()

    @pytest.fixture
    @patch.object(NodeCollection, "get", NodeCollectionMock.get)
    @patch.object(DockerClient, "info", DockerClientMock.info)
    def installer(self):
        """Returns an initialized partially mocked SwarmInstaller."""
        return SwarmInstaller({}, "docker-swarm", docker_client=DockerClient())

    @patch.object(NodeCollection, "get", NodeCollectionMock.get_not_manager)
    @patch.object(DockerClient, "info", DockerClientMock.info)
    def test_init_not_swarm_raises(self, docker_client):
        with pytest.raises(PluginError):
            SwarmInstaller({}, "docker-swarm", docker_client=docker_client)

    @patch.object(NodeCollection, "get", NodeCollectionMock.get)
    @patch.object(DockerClient, "info", DockerClientMock.info_not_swarm)
    def test_init_not_manager_raises(self, docker_client):
        with pytest.raises(PluginError):
            SwarmInstaller({}, "docker-swarm", docker_client=docker_client)

    def test_keep_secrets_limit(self, installer):
        tmp = installer.keep_secrets
        assert tmp == DockerClientMock.info() \
                                      .get("Swarm") \
                                      .get("Cluster") \
                                      .get("Spec") \
                                      .get("Orchestration") \
                                      .get("TaskHistoryRetentionLimit")

    def test_prepare(self):
        pass

    def test_more_info(self, installer):
        assert type(installer.more_info()) is str

    @patch.object(SecretCollection, "list", SecretCollectionMock.list)
    def test_is_secret_deployed(self, installer):
        assert installer.is_secret_deployed(
            "1.example.com",
            "cert",
            "AA:BB"
        ) is True

        assert installer.is_secret_deployed(
            "1.example.com",
            "cert",
            "AA:BB:CC"
        ) is False

        assert installer.is_secret_deployed(
            "2.example.com",
            "cert",
            "AA:BB"
        ) is True

    @patch.object( # Make sure created secrets always have a known ID.
        SecretCollection,
        "create",
        SecretCollectionMock.create_predefined(
            "abcdefg",
            "1.example.com_key_v123456",
            {
                "certbot.certificate-fingerprint": "AA:BB:CC",
                "certbot.domain": "1.example.com",
                "certbot.managed": "true",
                "certbot.name": "key",
                "certbot.version": "123456"
            }
        )
    )
    @patch.object( # Make sure secrets always exist when .get() is called.
        SecretCollection,
        "get",
        SecretCollectionMock.get_predefined(
            "abcdefg",
            "1.example.com_key_v123456",
            {}
        )
    )
    @patch("time.time", MagicMock(return_value=123456.0))
    def test_secret_from_file(self, installer):
        """
        This method is super hard to test. Some asserts are also done in
        SecretCollectionMock.create_predefined() because I couldn't figure
        out a way to spy calls to DockerClient.secrets.create() without
        mocking a ton of stuff. Anyway, this test should work!
        """

        ret = installer.secret_from_file(
            "1.example.com",
            "key",
            os.path.join(os.path.dirname(__file__), "assets", "key.pem"),
            "AA:BB:CC"
        )
        assert ret is not None
        assert ret.id == "abcdefg"

    @patch.object(SecretCollection, "list", SecretCollectionMock.list)
    def test_get_all_names(self, installer):
        tmp = installer.get_all_names()
        assert tmp == set(["1.example.com", "2.example.com"])

    def test_deploy_cert(self):
        pass

    @patch.object(SecretCollection, "list", SecretCollectionMock.list)
    def test_get_secrets(self, installer):
        tmp = installer.get_secrets("2.example.com", "cert", reverse=False)
        assert len(tmp) == 2
        assert tmp[0].id == "c"
        assert tmp[1].id == "e"

        tmp = installer.get_secrets("1.example.com", "chain", reverse=False)
        assert len(tmp) == 1
        assert tmp[0].id == "b"

        tmp = installer.get_secrets("1.example.com", "fullchain", reverse=False)
        assert tmp == []

        tmp = installer.get_secrets("3.example.com", "cert", reverse=False)
        assert tmp == []


    @patch.object(SecretCollection, "list", SecretCollectionMock.list)
    def test_get_secrets_reverse(self, installer):
        tmp = installer.get_secrets("2.example.com", "cert", reverse=True)
        assert len(tmp) == 2
        assert tmp[0].id == "e"
        assert tmp[1].id == "c"

        tmp = installer.get_secrets("1.example.com", "chain", reverse=True)
        assert len(tmp) == 1
        assert tmp[0].id == "b"

        tmp = installer.get_secrets("1.example.com", "fullchain", reverse=True)
        assert tmp == []

        tmp = installer.get_secrets("3.example.com", "cert", reverse=True)
        assert tmp == []

    def test_rm_oldest_secrets(self):
        pass

    def test_update_services(self):
        pass

    def test_enhance(self):
        pass

    def test_supported_enhancements(self, installer):
        assert installer.supported_enhancements() == []

    def test_save(self):
        pass

    def test_rollback_checkpoints(self):
        pass

    def test_recovery_routine(self):
        pass

    def test_config_test(self):
        pass

    def test_restart(self):
        pass
