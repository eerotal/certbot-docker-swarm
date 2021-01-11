"""Tests for SwarmInstaller."""

import os
import time
import pytest

import mock
from mock import patch, call, MagicMock, DEFAULT

from certbot.errors import PluginError
from docker.client import DockerClient
from docker.models.nodes import Node, NodeCollection
from docker.models.secrets import Secret, SecretCollection
from docker.models.services import Service, ServiceCollection
from docker.types.services import SecretReference

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
                    'Name': '1.example.com_cert_v0',
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
                    'Name': '1.example.com_chain_v0',
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
                    'Name': '2.example.com_cert_v0',
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
                    'Name': '2.example.com_chain_v0',
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
                    'Name': '2.example.com_cert_v1',
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
                    'Name': '2.example.com_chain_v1',
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


class ServiceCollectionDefs:
    @classmethod
    def list(cls):
        return [
            Service(attrs={
                "Spec": {
                    "ID": "qwerty",
                    "Name": "Test Service",
                    "TaskTemplate": {
                        "ContainerSpec": {
                            "Secrets": [
                                {
                                    "SecretID": "c",
                                    "SecretName": "example.com_cert_v0",
                                    "File": {
                                        "Name": "example.com_cert",
                                        "UID": "0",
                                        "GID": "0",
                                        "Mode": "292"
                                    }
                                },
                                {
                                    "SecretID": "d",
                                    "SecretName": "example.com_chain_v0",
                                    "File": {
                                        "Name": "example.com_chain",
                                        "UID": "0",
                                        "GID": "0",
                                        "Mode": "292"
                                    }
                                }
                            ]
                        }
                    }
                }
            })
        ]


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

    @pytest.mark.skip(reason="Nothing to test.")
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

    def test_deploy_cert(self, installer):
        # Certificate path.
        cp = os.path.join(os.path.dirname(__file__), "assets", "cert.pem")

        # Certificate fingerprint.
        cf = ("D7:5C:60:9E:BE:8F:78:67:1D:0E:16:98:80:96:3A:B5:"
              "FF:88:A7:94:19:75:6D:11:A0:3E:1F:33:21:90:54:7F")

        # This is the "keep" argument we expect is passed to
        # SwarmInstaller.rm_secrets().
        keep = DockerClientDefs.info() \
                               .get("Swarm") \
                               .get("Cluster") \
                               .get("Spec") \
                               .get("Orchestration") \
                               .get("TaskHistoryRetentionLimit")

        with patch.multiple(
            SwarmInstaller,
            is_secret_deployed=DEFAULT,
            secret_from_file=DEFAULT,
            update_services=DEFAULT,
            rm_secrets=DEFAULT
        ) as values:
            mock_is_deployed = values["is_secret_deployed"]
            mock_rm = values["rm_secrets"]
            mock_update = values["update_services"]
            mock_new = values["secret_from_file"]

            # Make sure all Secrets are considered not deployed.
            mock_is_deployed.return_value = False

            # Let's just deploy the certificate to all Secrets since
            # the Secret contents don't really matter anyway.
            installer.deploy_cert("1.example.com", cp, cp, cp, cp)

            # Assert that new Secrtes were created.
            mock_new.assert_has_calls([
                call("1.example.com", "cert", cp, cf),
                call("1.example.com", "key", cp, cf),
                call("1.example.com", "chain", cp, cf),
                call("1.example.com", "fullchain", cp, cf),
            ], any_order=True)

            # Assert that Services were updated.
            mock_update.assert_called_once()
            for arg in mock_update.call_args.args:
                assert arg is not None

            # Assert that old Secrets were removed.
            mock_rm.assert_has_calls([
                call("1.example.com", "cert", keep),
                call("1.example.com", "key", keep),
                call("1.example.com", "chain", keep),
                call("1.example.com", "fullchain", keep)
            ], any_order=True)

    def test_deploy_cert_already_deployed(self, installer):
        # Certificate path.
        cp = os.path.join(os.path.dirname(__file__), "assets", "cert.pem")

        # This is the "keep" argument we expect is passed to
        # SwarmInstaller.rm_secrets().
        keep = DockerClientDefs.info() \
                               .get("Swarm") \
                               .get("Cluster") \
                               .get("Spec") \
                               .get("Orchestration") \
                               .get("TaskHistoryRetentionLimit")

        with patch.multiple(
            SwarmInstaller,
            is_secret_deployed=DEFAULT,
            secret_from_file=DEFAULT,
            update_services=DEFAULT,
            rm_secrets=DEFAULT
        ) as values:
            mock_is_deployed = values["is_secret_deployed"]
            mock_rm = values["rm_secrets"]
            mock_update = values["update_services"]
            mock_new = values["secret_from_file"]

            # Make sure all Secrets are considered deployed.
            mock_is_deployed.return_value = True

            # Let's just deploy the certificate to all Secrets since
            # the Secret contents don't really matter anyway.
            installer.deploy_cert("1.example.com", cp, cp, cp, cp)

            # Make sure no new Secrets are created.
            mock_new.assert_not_called()

            # Make sure Service updates are still attempted.
            mock_update.assert_called_once()
            for arg in mock_update.call_args.args:
                assert arg is None

            # Assert that old Secrets are removed.
            mock_rm.assert_has_calls([
                call("1.example.com", "cert", keep),
                call("1.example.com", "key", keep),
                call("1.example.com", "chain", keep),
                call("1.example.com", "fullchain", keep)
            ], any_order=True)

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

    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_rm_secrets(self, installer):
        removed = set([])

        def record_removed(self, removed=removed):
            removed.add(self.id)

        with patch.object(Secret, "remove", record_removed):
            removed.clear()
            installer.rm_secrets("2.example.com", "cert", 0)
            assert removed == set(["c", "e"])

            removed.clear()
            installer.rm_secrets("2.example.com", "cert", 1)
            assert removed == set(["c"])

            removed.clear()
            installer.rm_secrets("2.example.com", "cert", 10)
            assert removed == set()

    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_rm_secrets_negative_keep(self, installer):
        with patch.object(Secret, "remove"):
            with pytest.raises(PluginError):
                installer.rm_secrets("2.example.com", "cert", -1)

    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    @patch.object(SecretCollection, "get", SecretCollectionDefs.get)
    def test_update_services(self, installer):
        cert = None
        chain = None

        # Find the correct Secrets from SecretCollectionDefs based on IDs.
        # For this test, these are supposed to the Secrets that *renew*
        # the Secrets in the test Service.
        for secret in SecretCollectionDefs.list():
            if secret.id == "e":
                cert = secret
            elif secret.id == "f":
                chain = secret

        with patch.object(Service, "update") as mock_update:
            installer.update_services(cert, chain, None, None)

            mock_update.assert_called_once()

            # Assert that all the correct Secrets were updated.
            updated = set()
            for ref in mock_update.call_args.kwargs.get("secrets"):
                assert isinstance(ref, SecretReference)
                updated.add(ref.get("SecretID"))

            assert updated == set(["e", "f"])

    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    @patch.object(SecretCollection, "get", SecretCollectionDefs.get)
    def test_update_services_not_updated(self, installer):
        cert = None
        chain = None

        # Find the correct Secrets from SecretCollectionDefs based on IDs.
        # For this test, these are supposed to be Secrets that *don't renew*
        # the Secrets in the test Service.
        for secret in SecretCollectionDefs.list():
            if secret.id == "a":
                cert = secret
            elif secret.id == "b":
                chain = secret

        with patch.object(Service, "update") as mock_update:
            installer.update_services(cert, chain, None, None)

            # Update shouldn't be called because the Secrets don't
            # renew the service Secrets.
            mock_update.assert_not_called()

    @patch.object(SecretCollection, "get", SecretCollectionDefs.get)
    def test_renew_secret_reference(self, installer):
        # SecretReference for Secret with ID: "c" in
        # SecretCollectionDefs.list()
        old_ref = SecretReference(
            "c",
            "2.example.com_cert_v0",
            "2.example.com_cert",
            "0",
            "0",
            "292"
        )

        # Use all test Secrets as candidates.
        candidates = SecretCollectionDefs.list()

        res = installer.renew_secret_reference(old_ref, candidates)
        assert res.get("SecretName") == "2.example.com_cert_v1"
        assert res.get("SecretID") == "e"
        assert res.get("File").get("Name") == old_ref.get("File").get("Name")
        assert res.get("File").get("UID") == old_ref.get("File").get("UID")
        assert res.get("File").get("GID") == old_ref.get("File").get("GID")
        assert res.get("File").get("Mode") == old_ref.get("File").get("Mode")

        res = installer.renew_secret_reference(old_ref, [])
        assert res == old_ref

    @pytest.mark.skip(reason="Nothing to test.")
    def test_enhance(self):
        pass

    def test_supported_enhancements(self, installer):
        assert installer.supported_enhancements() == []

    @pytest.mark.skip(reason="Nothing to test.")
    def test_save(self):
        pass

    @pytest.mark.skip(reason="Nothing to test.")
    def test_rollback_checkpoints(self):
        pass

    def test_recovery_routine(self):
        pass

    @pytest.mark.skip(reason="Nothing to test.")
    def test_config_test(self):
        pass

    @pytest.mark.skip(reason="Nothing to test.")
    def test_restart(self):
        pass
