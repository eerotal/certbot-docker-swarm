"""Tests for SwarmInstaller."""

import pytest
from mock import patch

from certbot.errors import PluginError
from docker.client import DockerClient
from docker.models.nodes import Node, NodeCollection
from docker.models.secrets import Secret, SecretCollection

from certbot_docker_swarm._internal.installer import SwarmInstaller

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

    def test_secret_from_file(self):
        pass

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
