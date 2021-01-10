"""Tests for SwarmInstaller."""

import os
import time
import pytest

import mock
from mock import patch, MagicMock, PropertyMock

from certbot.errors import PluginError
from docker.client import DockerClient
from docker.models.nodes import Node, NodeCollection
from docker.models.secrets import Secret, SecretCollection

from certbot_docker_swarm._internal.installer import SwarmInstaller
from certbot_docker_swarm._internal.installer import SwarmInstallerUtils


class NodeCollectionDefs:
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


class SecretCollectionDefs:
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


class DockerClientDefs:
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
    @patch.object(NodeCollection, "get", NodeCollectionDefs.get)
    @patch.object(DockerClient, "info", DockerClientDefs.info)
    def installer(self):
        """Returns an initialized partially mocked SwarmInstaller."""
        return SwarmInstaller({}, "docker-swarm", docker_client=DockerClient())

    @patch.object(NodeCollection, "get", NodeCollectionDefs.get_not_manager)
    @patch.object(DockerClient, "info", DockerClientDefs.info)
    def test_init_not_swarm_raises(self, docker_client):
        with pytest.raises(PluginError):
            SwarmInstaller({}, "docker-swarm", docker_client=docker_client)

    @patch.object(NodeCollection, "get", NodeCollectionDefs.get)
    @patch.object(DockerClient, "info", DockerClientDefs.info_not_swarm)
    def test_init_not_manager_raises(self, docker_client):
        with pytest.raises(PluginError):
            SwarmInstaller({}, "docker-swarm", docker_client=docker_client)

    def test_keep_secrets_limit(self, installer):
        tmp = installer.keep_secrets
        assert tmp == DockerClientDefs.info() \
                                      .get("Swarm") \
                                      .get("Cluster") \
                                      .get("Spec") \
                                      .get("Orchestration") \
                                      .get("TaskHistoryRetentionLimit")

    def test_prepare(self):
        pass

    def test_more_info(self, installer):
        assert type(installer.more_info()) is str

    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
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

    def test_secret_from_file(self, installer):
        # Define the Secret properties here for later use.
        secret_id = "abcdefg"
        secret_domain = "1.example.com"
        secret_name = "key"
        secret_version = "123456"
        secret_fingerprint = "AA:BB:CC"

        secret_filepath = os.path.join(
            os.path.dirname(__file__),
            "assets",
            "key.pem"
        )
        secret_fullname = SwarmInstallerUtils.SECRET_FORMAT.format(
            domain=secret_domain,
            name=secret_name,
            version=secret_version
        )
        secret_labels = {
            "certbot.certificate-fingerprint": secret_fingerprint,
            "certbot.domain": secret_domain,
            "certbot.managed": "true",
            "certbot.name": secret_name,
            "certbot.version": secret_version
        }

        secret = Secret({
            "ID": secret_id,
            "Spec": {
                "Name": secret_fullname,
                "Labels": secret_labels
            }
        })

        # Patch time.time() to always return a known value because
        # Secret IDs are generated from it.
        with patch("time.time", return_value=123456.0):
            with patch.object(DockerClient, "secrets") as mock_secrets:
                # Patch DockerClient.secrets.get() to return a known Secret.
                mock_secrets.get.return_value = secret

                # Patch DockerClient.secrets.create() to return a known Secret.
                # For some reason the original method seems to return a Secret
                # with only the "ID" attribute set so let's emulate that for
                # consistency.
                mock_secrets.create.return_value = Secret({"ID": secret_id})

                ret = installer.secret_from_file(
                    secret_domain,
                    secret_name,
                    secret_filepath,
                    secret_fingerprint
                )

                # Assert that the correct Secret was created.
                mock_secrets.create.assert_called_once_with(
                    name=secret_fullname,
                    data=mock.ANY,
                    labels=secret_labels
                )

                # Assert that the correct secret is returned.
                assert ret is not None
                assert ret.id == secret_id
                assert ret.attrs == secret.attrs

    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_get_all_names(self, installer):
        tmp = installer.get_all_names()
        assert tmp == set(["1.example.com", "2.example.com"])

    def test_deploy_cert(self):
        pass

    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_get_secrets(self, installer):
        t = installer.get_secrets("2.example.com", "cert", reverse=False)
        assert len(t) == 2
        assert t[0].id == "c"
        assert t[1].id == "e"

        t = installer.get_secrets("1.example.com", "chain", reverse=False)
        assert len(t) == 1
        assert t[0].id == "b"

        t = installer.get_secrets("1.example.com", "fullchain", reverse=False)
        assert t == []

        t = installer.get_secrets("3.example.com", "cert", reverse=False)
        assert t == []

    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_get_secrets_reverse(self, installer):
        t = installer.get_secrets("2.example.com", "cert", reverse=True)
        assert len(t) == 2
        assert t[0].id == "e"
        assert t[1].id == "c"

        t = installer.get_secrets("1.example.com", "chain", reverse=True)
        assert len(t) == 1
        assert t[0].id == "b"

        t = installer.get_secrets("1.example.com", "fullchain", reverse=True)
        assert t == []

        t = installer.get_secrets("3.example.com", "cert", reverse=True)
        assert t == []

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
