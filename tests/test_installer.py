"""Tests for SwarmInstaller."""

import pytest
from unittest.mock import patch
from types import SimpleNamespace

from certbot.errors import PluginError
from docker.client import DockerClient
from docker.models.nodes import NodeCollection

from certbot_docker_swarm._internal.installer import SwarmInstaller

class NodeCollectionMock:
    @classmethod
    def get(cls, *args, **kwargs):
        ns = SimpleNamespace()
        ns.attrs = {
            "Spec": {
                "Role": "manager"
            }
        }
        return ns

    @classmethod
    def get_not_manager(cls, *args, **kwargs):
        tmp = cls.get()
        tmp.attrs["Spec"]["Role"] = "node"
        return tmp

class DockerClientMock:
    @classmethod
    def info(cls, *args, **kwargs):
        return {
            "Swarm": {
                "NodeID": "123456789",
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

    @patch.object(NodeCollection, "get", NodeCollectionMock.get_not_manager)
    def test_init_not_swarm_raises(self, docker_client):
        with pytest.raises(PluginError):
            SwarmInstaller({}, "docker-swarm", docker_client=docker_client)

    @patch.object(NodeCollection, "get", NodeCollectionMock.get)
    @patch.object(DockerClient, "info", DockerClientMock.info_not_swarm)
    def test_init_not_manager_raises(self, docker_client):
        with pytest.raises(PluginError):
            SwarmInstaller({}, "docker-swarm", docker_client=docker_client)

    @patch.object(NodeCollection, "get", NodeCollectionMock.get)
    @patch.object(DockerClient, "info", DockerClientMock.info)
    def test_keep_secrets_limit(self, docker_client):
        s = SwarmInstaller({}, "docker-swarm", docker_client=docker_client)

        tmp = s.keep_secrets
        assert tmp == DockerClientMock.info() \
                                      .get("Swarm") \
                                      .get("Cluster") \
                                      .get("Spec") \
                                      .get("Orchestration") \
                                      .get("TaskHistoryRetentionLimit")
