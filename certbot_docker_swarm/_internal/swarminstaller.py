"""Docker Swarm installer"""

import os
import time
import logging

from datetime import datetime

import zope.interface
from acme.magic_typing import List

from certbot.interfaces import IInstaller, IPluginFactory
from certbot.plugins.common import Installer
from certbot.errors import PluginError

import docker
from docker.errors import APIError
from docker.models.secrets import Secret

from certbot_docker_swarm._internal.util.secretutils import SecretUtils
from certbot_docker_swarm._internal.models.secretspec import SecretSpec

logger = logging.getLogger(__name__)


@zope.interface.implementer(IInstaller)
@zope.interface.provider(IPluginFactory)
class SwarmInstaller(Installer):
    """Docker Swarm installer."""

    description = "Docker Swarm Installer"

    def __init__(self, config, name, docker_client=None):
        if docker_client is not None:
            # Use DockerClient supplied by caller if it exists.
            # This is mainly used for testing.
            self.docker_client = docker_client
        else:
            # Normally create DockerClient from env.
            self.docker_client = docker.from_env()

        super().__init__(config, name)

        self.config = config
        self.conf_file = os.path.join(config.config_dir, "docker-swarm.json")

        info = self.docker_client.info()
        node_id = info.get("Swarm").get("NodeID")
        node = self.docker_client.nodes.get(node_id)

        node_state = info.get("Swarm").get("LocalNodeState")
        node_role = node.attrs.get("Spec").get("Role")

        # Make sure we are running on a Docker Swarm manager node.
        if node_state != "active":
            raise PluginError("Swarm not active.")
        if node_role != "manager":
            raise PluginError("Not running on a Swarm Manager node.")

        # Use the Docker task retention limit as the number of old
        # secrets to keep. This makes sure enough secrets for historic
        # tasks are always kept in the Swarm.
        self.keep_secrets = info.get("Swarm") \
                                .get("Cluster") \
                                .get("Spec") \
                                .get("Orchestration") \
                                .get("TaskHistoryRetentionLimit")

        # Create a new empty SecretSpec.
        self.secret_spec = SecretSpec(self.docker_client)

    def prepare(self):
        # type: () -> None
        """Prepare the SwarmInstaller plugin."""

        backups = os.listdir(self.config.backup_dir)
        if self.config.verb != "rollback" and not backups:
            # No checkpoints exist yet and not rolling back.
            # -> Create the initial configuration checkpoint.

            logger.info("Creating initial configuration checkpoint.")

            if not os.path.isfile(self.conf_file):
                self.secret_spec.write(self.conf_file)

            note = ("Initial Docker Swarm Secret config at {}.\n"
                    .format(datetime.now().isoformat()))
            self.add_to_checkpoint(set([self.conf_file]), note, False)
            self.finalize_checkpoint("Initial Docker Swarm configuration.")

    def more_info(self):  # pylint: disable=no-self-use
        # type: () -> str
        """Return a human-readable help string.

        :return: A help string.
        :rtype str:
        """

        return "Installs certificates as Docker Swarm Secrets and " \
               "automatically updates Docker Swarm Services to use" \
               "the renewed secrets."

    def get_all_names(self):
        # type: () -> List[str]
        """Get all domain names that have at least one existing secret.

        :rtype: Set[str]
        """

        f = {}
        f[SecretUtils.L_MANAGED] = lambda x: x == "true"
        f[SecretUtils.L_DOMAIN] = lambda x: x is not None
        f[SecretUtils.L_NAME] = lambda x: x is not None
        f[SecretUtils.L_VERSION] = lambda x: x is not None
        f[SecretUtils.L_FINGERPRINT] = lambda x: x is not None

        s = self.docker_client.secrets.list()
        s = SecretUtils.filter_secrets(s, f)

        return {SecretUtils.get_secret_domain(x) for x in s}

    def deploy_cert(  # pylint: disable=too-many-arguments
        self,
        domain,
        cert_path,
        key_path,
        chain_path,
        fullchain_path
    ):
        # type: (str, str, str, str, str) -> None
        """Create Docker Swarm Secrets from certificates.

        :param str domain: Certificate domain.
        :param str cert_path: Path to the certificate file.
        :param str key_path: Path to the private key file.
        :param str chain_path: Path to the certificate chain file.
        :param str fullchain_path: Path to the fullchain file.
        """

        fp = SecretUtils.get_x509_fingerprint(cert_path)

        cert = None
        key = None
        chain = None
        fc = None

        # Create new secrets.
        if not self.is_secret_deployed(domain, "cert", fp):
            cert = self.secret_from_file(domain, "cert", cert_path, fp)
        if not self.is_secret_deployed(domain, "key", fp):
            key = self.secret_from_file(domain, "key", key_path, fp)
        if not self.is_secret_deployed(domain, "chain", fp):
            chain = self.secret_from_file(domain, "chain", chain_path, fp)
        if not self.is_secret_deployed(domain, "fullchain", fp):
            fc = self.secret_from_file(domain, "fullchain", fullchain_path, fp)

        if not cert or not key or not chain or not fc:
            logger.info("Some secrets already deployed. They were skipped.")

        if cert is not None:
            self.secret_spec.update_refs(cert)
        if key is not None:
            self.secret_spec.update_refs(key)
        if chain is not None:
            self.secret_spec.update_refs(chain)
        if fc is not None:
            self.secret_spec.update_refs(fc)

    def enhance(self, domain, enhancement, options=None):
        # type: (str, str, dict) -> None
        """Enhance SSL config."""

    def supported_enhancements(self):  # pylint: disable=no-self-use
        # type: () -> List[str]
        """Return a list of supported enhancements."""
        return []

    def save(self, title=None, temporary=False):
        # type: (str, bool) -> None
        """Save changes to Secret configuration.

        :param str title: Checkpoint title.
        :param bool temporary: Whether the checkpoint is temporary.
        """

        note = ("Update Docker Swarm Secret config at {}.\n"
                .format(datetime.now().isoformat()))
        self.add_to_checkpoint(set([self.conf_file]), note, temporary)

        if title and not temporary:
            self.finalize_checkpoint(title)

        self.update_services(self.secret_spec)
        self.secret_spec.write(self.conf_file)
        self.rm_secrets(self.keep_secrets)

    def rollback_checkpoints(self, rollback=1):
        # type: (int) -> None
        """Revert 'rollback' configuration checkpoints.

        :param int rollback: The number of checkpoints to rollback.
        """

        backups = os.listdir(self.config.backup_dir)
        if backups:
            logger.info("Rolling back Secret configuration file.")
            super().rollback_checkpoints(rollback)
            self.secret_spec.read(self.conf_file)

            logger.info("Updating Docker Swarm Services.")
            self.update_services(self.secret_spec)
        else:
            logger.info("No checkpoints found. Won't rollback.")

    def config_test(self):
        # type: () -> None
        """Config test."""

    def restart(self):
        # type: () -> None
        """Restart server."""

    def update_services(self, secret_spec):
        # type: (SecretSpec) -> None
        """Update Swarm Services based on the current SecretSpec.

        :param SecretSpec spec: The SecretSpec to use for Services.
        """

        for service_id in secret_spec.services:
            service = self.docker_client.services.get(service_id)
            service.update(secrets=secret_spec.get_refs(service_id))

    def is_secret_deployed(self, domain, name, fingerprint):
        # type: (str, str, str) -> bool
        """Check whether a secret is already deployed based on fingerprints.

        :param domain str: The domain the secret authenticates.
        :param name str: The name of the secret.
        :param fingerprint str: The fingerprint of the *certificate*
                                corresponding to this secret.

        :return: True if deployed, False otherwise.
        :rtype: bool
        """

        existing_secrets = self.get_secrets(domain, name)

        if len(existing_secrets) != 0:
            newest = existing_secrets[-1]
            newest_fp = SecretUtils.get_secret_fingerprint(newest)

            if newest_fp == fingerprint:
                # Skip deployment if the secret has already been deployed.
                return True

        return False

    def secret_from_file(self, domain, name, filepath, fingerprint):
        # type: (str, str, str, str) -> Secret
        """ Create a Docker Swarm secret from a certificate file.

        :param domain str: The domain the secret authenticates.
        :param name str: The name of the secret.
        :param filepath str: The file path of the secret.
        :param fingerprint str: The fingerprint of the *certificate*
                                corresponding to this secret.

        :return: The created Secret.
        :rtype: Secret

        :raises: PluginError if secret creation failed.
        """

        version = str(int(time.time()))

        labels = {}
        labels[SecretUtils.L_MANAGED] = "true"
        labels[SecretUtils.L_DOMAIN] = domain
        labels[SecretUtils.L_NAME] = name
        labels[SecretUtils.L_VERSION] = version
        labels[SecretUtils.L_FINGERPRINT] = fingerprint

        name = SecretUtils.SECRET_FORMAT.format(
            domain=domain,
            name=name,
            version=version
        )

        with open(filepath, "r") as f:
            sid = None
            try:
                sid = self.docker_client.secrets.create(
                    name=name,
                    data=f.read(),
                    labels=labels
                ).id
            except APIError as e:
                raise PluginError(
                    "Failed to create secret {}: {}"
                    .format(name, str(e))
                ) from e

            logger.info("Created secret %s from file %s.", name, filepath)

            return self.docker_client.secrets.get(sid)

    def get_secrets(self, domain, name, reverse=False):
        # type: (str, str) -> List[Secret]
        """Get all secrets of a specific type for a domain.

        The resulting list of secrets is sorted based on secret
        versions from lowest to highest.

        :param str domain: Secret domain.
        :param str name: Secret name.
        :param bool reverse: Sort the Secrets in reverse order.

        :return: A list of secrets.
        :rtype: List[Secret]
        """

        f = {}
        f[SecretUtils.L_MANAGED] = lambda x: x == "true"
        f[SecretUtils.L_DOMAIN] = lambda x: x == domain
        f[SecretUtils.L_NAME] = lambda x: x == name
        f[SecretUtils.L_VERSION] = lambda x: x is not None
        f[SecretUtils.L_FINGERPRINT] = lambda x: x is not None

        s = self.docker_client.secrets.list()
        s = SecretUtils.filter_secrets(s, f)
        s = SecretUtils.sort_secrets(
            s,
            SecretUtils.L_VERSION,
            reverse
        )

        return s

    def rm_secrets(self, keep):
        # type: (str, str, int) -> None
        """Remove oldest secrets of all managed domains.

        :param keep int: How many secrets to keep.

        :raises: PluginError if keep < 0.
        """

        if keep < 0:
            raise PluginError("Number of Secrets to keep must be positive.")

        remove_cnt = 0
        domains = self.get_all_names()

        for domain in domains:
            logger.info("Removing old secrets for domain %s.", domain)
            for name in ["cert", "key", "chain", "fullchain"]:
                remove = self.get_secrets(domain, name, True)[keep:]
                remove_cnt += len(remove)

                for secret in remove:
                    try:
                        secret.remove()
                    except APIError as e:
                        logger.error(
                            "Failed to remove secret %s (id: %s): %s",
                            secret.name, secret.id, str(e)
                        )
                        remove_cnt -= 1

                    logger.info(
                        "Removed secret %s (id: %s)",
                        secret.name, secret.id
                    )

        logger.info("Removed %s secrets in total.", remove_cnt)
