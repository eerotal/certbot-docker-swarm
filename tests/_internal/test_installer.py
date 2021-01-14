"""Tests for SwarmInstaller."""

import os
import time
import pytest
import tempfile
import shutil

import mock
from mock import patch, call, MagicMock, DEFAULT

from certbot.plugins.common import Installer
from certbot.errors import PluginError
from certbot._internal.configuration import NamespaceConfig
from certbot._internal.constants import CLI_DEFAULTS

from docker.client import DockerClient
from docker.models.nodes import Node, NodeCollection
from docker.models.secrets import Secret, SecretCollection
from docker.models.services import Service, ServiceCollection
from docker.types.services import SecretReference

from certbot_docker_swarm._internal.installer import SwarmInstaller
from certbot_docker_swarm._internal.util.secretutils import SecretUtils
from certbot_docker_swarm._internal.models.secretspec import SecretSpec

from tests._internal.fakes.docker import *
from tests.config.defs import ASSET_PATH


class TestSwarmInstaller():
    @pytest.fixture
    def config(self):
        # Setup
        tempdir = tempfile.mkdtemp()
        config = NamespaceConfig(MagicMock(**CLI_DEFAULTS))
        config.verb = "run"
        config.config_dir = os.path.join(tempdir, "config")
        config.work_dir = os.path.join(tempdir, "work")
        config.logs_dir = os.path.join(tempdir, "logs")
        config.backup_dir = os.path.join(tempdir, "backup")
        config.cert_path = CLI_DEFAULTS['auth_cert_path']
        config.fullchain_path = CLI_DEFAULTS['auth_chain_path']
        config.chain_path = CLI_DEFAULTS['auth_chain_path']
        config.server = "https://example.com"

        # Make sure directories exist.
        if not os.path.isdir(config.config_dir):
            os.mkdir(config.config_dir)
        if not os.path.isdir(config.work_dir):
            os.mkdir(config.work_dir)
        if not os.path.isdir(config.logs_dir):
            os.mkdir(config.logs_dir)

        yield config

        # Teardown
        shutil.rmtree(tempdir)

    @pytest.fixture
    def docker_client(self):
        return DockerClient()

    @pytest.fixture
    @patch.object(NodeCollection, "get", NodeCollectionDefs.get)
    @patch.object(DockerClient, "info", DockerClientDefs.info)
    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    def installer(self, config):
        """Returns an initialized partially mocked SwarmInstaller."""
        return SwarmInstaller(
            config,
            "docker-swarm",
            docker_client=DockerClient()
        )

    @pytest.mark.dependency()
    def test_init(self, installer):
        # Let's just pass here because any possible errors will
        # be in the TestSwarmInstaller.installer() fixture.
        pass

    @patch.object(NodeCollection, "get", NodeCollectionDefs.get_not_manager)
    @patch.object(DockerClient, "info", DockerClientDefs.info)
    def test_init_not_swarm_raises(self, docker_client, config):
        with pytest.raises(PluginError):
            SwarmInstaller(config, "docker-swarm", docker_client=docker_client)

    @patch.object(NodeCollection, "get", NodeCollectionDefs.get)
    @patch.object(DockerClient, "info", DockerClientDefs.info_not_swarm)
    def test_init_not_manager_raises(self, docker_client, config):
        with pytest.raises(PluginError):
            SwarmInstaller(config, "docker-swarm", docker_client=docker_client)

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_keep_secrets_limit(self, installer):
        tmp = installer.keep_secrets
        assert tmp == DockerClientDefs.info() \
                                      .get("Swarm") \
                                      .get("Cluster") \
                                      .get("Spec") \
                                      .get("Orchestration") \
                                      .get("TaskHistoryRetentionLimit")

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_prepare(self, installer):
        with patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = []

            with patch.multiple(
                SwarmInstaller,
                add_to_checkpoint=DEFAULT,
                finalize_checkpoint=DEFAULT
            ) as values:
                mock_add_to_checkpoint = values["add_to_checkpoint"]
                mock_finalize_checkpoint = values["finalize_checkpoint"]

                installer.prepare()

                assert os.path.isfile(installer.conf_file)
                mock_add_to_checkpoint.assert_called()
                mock_finalize_checkpoint.assert_called_once()

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_prepare_on_rollback(self, installer):
        # The initial config checkpoint should not be created
        # if the user ran "certbot rollback".
        installer.config.verb = "rollback"

        with patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = []

            with patch.multiple(
                SwarmInstaller,
                add_to_checkpoint=DEFAULT,
                finalize_checkpoint=DEFAULT
            ) as values:
                mock_add_to_checkpoint = values["add_to_checkpoint"]
                mock_finalize_checkpoint = values["finalize_checkpoint"]

                installer.prepare()
                mock_finalize_checkpoint.assert_not_called()

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_prepare_backups_exist(self, installer):
        with patch('os.listdir') as mock_listdir:
            # The initial config checkpoint should not be created if
            # checkpoints already exist.
            mock_listdir.return_value = ["dummy"]

            with patch.multiple(
                SwarmInstaller,
                add_to_checkpoint=DEFAULT,
                finalize_checkpoint=DEFAULT
            ) as values:
                mock_add_to_checkpoint = values["add_to_checkpoint"]
                mock_finalize_checkpoint = values["finalize_checkpoint"]

                installer.prepare()
                mock_finalize_checkpoint.assert_not_called()

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_more_info(self, installer):
        assert type(installer.more_info()) is str

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
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

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_secret_from_file(self, installer):
        # Define the Secret properties here for later use.
        secret_id = "abcdefg"
        secret_domain = "1.example.com"
        secret_name = "key"
        secret_version = "123456"
        secret_fingerprint = "AA:BB:CC"

        secret_filepath = os.path.join(ASSET_PATH, "key.pem")
        secret_fullname = SecretUtils.SECRET_FORMAT.format(
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

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_get_all_names(self, installer):
        tmp = installer.get_all_names()
        assert tmp == set(["1.example.com", "2.example.com"])

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_deploy_cert(self, installer):
        # Certificate path.
        cp = os.path.join(ASSET_PATH, "cert.pem")

        # Certificate fingerprint.
        cf = ("D7:5C:60:9E:BE:8F:78:67:1D:0E:16:98:80:96:3A:B5:"
              "FF:88:A7:94:19:75:6D:11:A0:3E:1F:33:21:90:54:7F")

        with patch.multiple(
            SwarmInstaller,
            is_secret_deployed=DEFAULT,
            secret_from_file=DEFAULT
        ) as values:
            mock_is_secret_deployed = values["is_secret_deployed"]
            mock_secret_from_file = values["secret_from_file"]

            with patch.object(SecretSpec, "update_refs") as mock_update_refs:
                # Make sure all Secrets are considered not deployed.
                mock_is_secret_deployed.return_value = False

                # Let's just deploy the certificate to all Secrets since
                # the Secret contents don't really matter anyway.
                installer.deploy_cert("1.example.com", cp, cp, cp, cp)

                # Assert that new Secrtes were created.
                mock_secret_from_file.assert_has_calls([
                    call("1.example.com", "cert", cp, cf),
                    call("1.example.com", "key", cp, cf),
                    call("1.example.com", "chain", cp, cf),
                    call("1.example.com", "fullchain", cp, cf),
                ], any_order=True)

                # Assert that the SecretSpec was updated.
                mock_update_refs.assert_called()

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_deploy_cert_already_deployed(self, installer):
        # Certificate path.
        cp = os.path.join(ASSET_PATH, "cert.pem")

        with patch.multiple(
            SwarmInstaller,
            is_secret_deployed=DEFAULT,
            secret_from_file=DEFAULT
        ) as values:
            mock_is_secret_deployed = values["is_secret_deployed"]
            mock_secret_from_file = values["secret_from_file"]

            with patch.object(SecretSpec, "update_refs") as mock_update_refs:
                # Make sure all Secrets are considered deployed.
                mock_is_secret_deployed.return_value = True

                # Let's just deploy the certificate to all Secrets since
                # the Secret contents don't really matter anyway.
                installer.deploy_cert("1.example.com", cp, cp, cp, cp)

                # Assert that the SecretSpec was not updated.
                mock_update_refs.assert_not_called()

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
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

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
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

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_rm_secrets(self, installer):
        removed = set([])

        def record_removed(self):
            removed.add(self.id)

        with patch.object(Secret, "remove", record_removed):
            installer.rm_secrets(0)
            assert removed == set(["a", "b", "c", "d", "e", "f"])

            removed = set([])
            installer.rm_secrets(1)
            assert removed == set(["c", "d"])

            removed = set([])
            installer.rm_secrets(5)
            assert removed == set([])

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    @patch.object(SecretCollection, "list", SecretCollectionDefs.list)
    def test_rm_secrets_negative_keep(self, installer):
        with patch.object(Secret, "remove"):
            with pytest.raises(PluginError):
                installer.rm_secrets(-1)

    @pytest.mark.skip(reason="Nothing to test.")
    def test_enhance(self):
        pass

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_supported_enhancements(self, installer):
        assert installer.supported_enhancements() == []

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_save(self, installer):
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
            add_to_checkpoint=DEFAULT,
            finalize_checkpoint=DEFAULT,
            rm_secrets=DEFAULT,
            update_services=DEFAULT
        ) as values:
            with patch.object(SecretSpec, "write") as mock_write:
                mock_add_to_checkpoint = values["add_to_checkpoint"]
                mock_finalize_checkpoint = values["finalize_checkpoint"]
                mock_rm_secrets = values["rm_secrets"]
                mock_update_services = values["update_services"]

                installer.save("Test title", False)

                # Assert that the config file was added to a checkpoint.
                mock_add_to_checkpoint.assert_called_once_with(
                    set([installer.conf_file]),
                    mock.ANY,
                    False
                )
                mock_finalize_checkpoint.assert_called_once_with("Test title")

                # Assert that Services were updated.
                mock_update_services.assert_called_once()
                mock_write.assert_called_once_with(installer.conf_file)
                mock_rm_secrets.assert_called_once_with(keep)

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    @patch.object(ServiceCollection, "get", ServiceCollectionDefs.get)
    def test_update_services(self, installer, docker_client):
        # This should also depend on TestSecretSpec tests but I
        # can't get such dependencies to work.
        spec = SecretSpec(docker_client)

        with patch.object(Service, "update") as mock_update:
            installer.update_services(spec)

            calls = []
            for service_id in spec.services:
                calls.append(call(secrets=spec.get_refs(service_id)))

            mock_update.assert_has_calls(calls)

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    @patch.object(Installer, "rollback_checkpoints", lambda x, y: None)
    @patch.object(ServiceCollection, "list", ServiceCollectionDefs.list)
    def test_rollback_checkpoints(self, installer, docker_client):
        # This should also depend on TestSecretSpec tests but I
        # can't get such dependencies to work.
        s = SecretSpec(docker_client, spec=None)
        s.write(installer.conf_file)

        with patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = ["dummy"]
            with patch.object(SwarmInstaller, "update_services") as mock_up:
                installer.rollback_checkpoints()
                mock_up.assert_called_once()

    @pytest.mark.dependency(depends=["TestSwarmInstaller::test_init"])
    def test_rollback_checkpoints_no_previous(self, installer, docker_client):
        # This should also depend on TestSecretSpec tests but I
        # can't get such dependencies to work.
        s = SecretSpec(docker_client, spec=None)
        s.write(installer.conf_file)

        with patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = []
            with patch.object(SwarmInstaller, "update_services") as mock_up:
                installer.rollback_checkpoints(rollback=1)
                mock_up.assert_not_called()

    @pytest.mark.skip(reason="Nothing to test.")
    def test_config_test(self):
        pass

    @pytest.mark.skip(reason="Nothing to test.")
    def test_restart(self):
        pass
