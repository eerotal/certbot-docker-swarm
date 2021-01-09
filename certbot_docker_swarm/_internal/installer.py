"""Docker Swarm installer"""

import time
import logging

import zope.interface
from acme.magic_typing import List, Optional

from certbot.interfaces import IInstaller, IPluginFactory
from certbot.plugins.common import Plugin
from certbot.errors import PluginError

import docker
from docker.errors import APIError
from docker.types.services import SecretReference
from docker.models.secrets import Secret

from .utils import SwarmInstallerUtils

logger = logging.getLogger(__name__)


@zope.interface.implementer(IInstaller)
@zope.interface.provider(IPluginFactory)
class SwarmInstaller(Plugin):
    """Docker Swarm installer."""

    description = "Docker Swarm Installer"

    def __init__(self, *args, **kwargs):
        if "docker_client" in kwargs:
            # Use DockerClient supplied by caller if it exists.
            # This is mainly used for testing.
            self.docker_client = kwargs["docker_client"]
            del kwargs["docker_client"]
        else:
            # Normally create DockerClient from env.
            self.docker_client = docker.from_env()

        self.old_secret_refs = {}

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

        super(SwarmInstaller, self).__init__(*args, **kwargs)

    def prepare(self):
        # type: () -> None
        pass

    def more_info(self):
        # type: () -> str
        """Return a human-readable help string.

        :return: A help string.
        :rtype str:
        """

        return "Installs certificates as Docker Swarm Secrets and " \
               "automatically updates Docker Swarm Services to use" \
               "the renewed secrets."

    def secret_from_file(self, domain, name, filepath, fingerprint):
        # type: (str, str, str, str) -> Optional[Secret]
        """ Create a Docker Swarm secret from a certificate file.

        :param domain str: The domain the secret authenticates.
        :param name str: The name of the secret.
        :param filepath str: The file path of the secret.
        :param fingerprint str: The fingerprint of the *certificate*
                                corresponding to this secret.

        :return: The created Secret or None if not created.
        :rtype: Optional[Secret]

        :raises: PluginError if secret creation failed.
        """

        existing_secrets = self.get_secrets(domain, name)

        if len(existing_secrets) != 0:
            newest = existing_secrets[-1]
            newest_fp = SwarmInstallerUtils.get_secret_fingerprint(newest)

            if newest_fp == fingerprint:
                # Skip deployment if the secret has already been deployed.
                logger.info(
                    "{} with fingerprint {} already deployed. Skipping."
                    .format(newest.name, fingerprint)
                )
                return None

        version = str(int(time.time()))

        labels = {}
        labels[SwarmInstallerUtils.L_MANAGED] = "true"
        labels[SwarmInstallerUtils.L_DOMAIN] = domain
        labels[SwarmInstallerUtils.L_NAME] = name
        labels[SwarmInstallerUtils.L_VERSION] = version
        labels[SwarmInstallerUtils.L_FINGERPRINT] = fingerprint

        name = SwarmInstallerUtils.SECRET_FORMAT.format(
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
                )

            logger.info(
                "Created secret {} from file {}."
                .format(name, filepath)
            )

            return self.docker_client.secrets.get(sid)

    def get_all_names(self):
        # type: () -> List[str]
        """Get all domain names that have at least one existing secret.

        :rtype: Set[str]
        """

        f = {}
        f[SwarmInstallerUtils.L_MANAGED] = lambda x: x == "true"
        f[SwarmInstallerUtils.L_DOMAIN] = lambda x: x is not None
        f[SwarmInstallerUtils.L_NAME] = lambda x: x is not None
        f[SwarmInstallerUtils.L_VERSION] = lambda x: x is not None
        f[SwarmInstallerUtils.L_FINGERPRINT] = lambda x: x is not None

        s = self.docker_client.secrets.list()
        s = SwarmInstallerUtils.filter_secrets(s, f)

        return set([SwarmInstallerUtils.get_secret_domain(x) for x in s])

    def deploy_cert(
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

        fp = SwarmInstallerUtils.get_x509_fingerprint(cert_path)

        # Create new secrets.
        cert = self.secret_from_file(domain, "cert", cert_path, fp)
        key = self.secret_from_file(domain, "key", key_path, fp)
        chain = self.secret_from_file(domain, "chain", chain_path, fp)
        fchain = self.secret_from_file(domain, "fullchain", fullchain_path, fp)

        # Update services.
        self.update_services(cert, key, chain, fchain)

        # Remove old secrets.
        n = self.rm_oldest_secrets(domain, "cert", self.keep_secrets)
        n += self.rm_oldest_secrets(domain, "key", self.keep_secrets)
        n += self.rm_oldest_secrets(domain, "chain", self.keep_secrets)
        n += self.rm_oldest_secrets(domain, "fullchain", self.keep_secrets)

        logger.info("Removed {} old secrets.".format(n))

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
        f[SwarmInstallerUtils.L_MANAGED] = lambda x: x == "true"
        f[SwarmInstallerUtils.L_DOMAIN] = lambda x: x == domain
        f[SwarmInstallerUtils.L_NAME] = lambda x: x == name
        f[SwarmInstallerUtils.L_VERSION] = lambda x: x is not None
        f[SwarmInstallerUtils.L_FINGERPRINT] = lambda x: x is not None

        s = self.docker_client.secrets.list()
        s = SwarmInstallerUtils.filter_secrets(s, f)
        s = SwarmInstallerUtils.sort_secrets(
            s,
            SwarmInstallerUtils.L_VERSION,
            reverse
        )

        return s

    def rm_oldest_secrets(self, domain, name, keep):
        # type: (str, str, int) -> int
        """Remove oldest secrets of a specific type for a specific domain.

        :param str domain: The domain whose secrets to remove.
        :param str name: The secret name to remove, eg. cert, key, ...
        :param keep int: How many secrets to keep.

        :return: The number of secrets removed.
        :rtype: int
        """

        remove = self.get_secrets(domain, name, True)[keep:]
        n = len(remove)

        for secret in remove:
            try:
                secret.remove()
            except APIError as e:
                logger.error(
                    "Failed to remove secret {} (id: {}): {}"
                    .format(secret.name, secret.id, str(e))
                )
                n -= 1

            logger.info(
                "Removed secret {} (id: {})"
                .format(secret.name, secret.id)
            )

        return n

    def update_services(self, cert, key, chain, fchain):
        # type: (Secret, Secret, Secret, Secret) -> None
        """Update Docker Swarm Services to use renewed secrets.

        :param Secret cert: Renewed certificate Secret.
        :param Secret key: Renewed private key Secret.
        :param Secret chain: Renewed certificate chain Secret.
        :param Secret fchain: Renewed fullchain Secret.
        """

        renew_candidates = list(filter(
            lambda x: x is not None,
            [cert, key, chain, fchain]
        ))

        if len(renew_candidates) == 0:
            logger.info("No secrets renewed. Skipping service update.")
            return

        logger.info("Updating Docker Swarm Services.")
        logger.debug(
            "Secret renew candidates: {}"
            .format(", ".join([x.name for x in renew_candidates]))
        )

        for service in self.docker_client.services.list():
            logger.info(
                "Working in service {} (id: {})"
                .format(service.name, service.id)
            )

            dirty = False
            new_secret_refs = []
            old_secret_refs = []

            secret_confs = service.attrs.get("Spec") \
                                        .get("TaskTemplate") \
                                        .get("ContainerSpec") \
                                        .get("Secrets")

            # Skip services with no secrets.
            if secret_confs is None:
                logger.debug("--> No secrets in service.")
                continue

            for tmp in secret_confs:
                old = self.docker_client.secrets.get(tmp.get("SecretID"))

                # Check whether any of the secrets in renew_candidates
                # renew the old secret.
                update_id = None
                update_name = None
                for new in renew_candidates:
                    logger.debug(
                        "--> Checking if {} renews {}."
                        .format(new.name, old.name)
                    )
                    if SwarmInstallerUtils.secret_renews(old, new):
                        update_id = new.id
                        update_name = new.name
                        dirty = True

                        logger.info(
                            "--> Update {}: {} -> {}"
                            .format(
                                tmp.get("File").get("Name"),
                                tmp.get("SecretName"),
                                new.name
                            )
                        )

                        break

                if update_id is None:
                    # None of the secrets in renew_candidates renew
                    # the old secret -> use the old secret as-is.
                    update_id = tmp.get("SecretID")
                    update_name = tmp.get("SecretName")

                fpar = [
                    tmp.get("File").get("Name"),
                    tmp.get("File").get("UID"),
                    tmp.get("File").get("GID"),
                    tmp.get("File").get("Mode")
                ]

                # Store old SecretReference.
                old_secret_refs.append(SecretReference(
                    tmp.get("SecretID"),
                    tmp.get("SecretName"),
                    *fpar
                ))

                # Create new SecretReference.
                new_secret_refs.append(SecretReference(
                    update_id,
                    update_name,
                    *fpar
                ))

            if dirty:
                logger.info("--> Committing changes.")
                self.old_secret_refs[service.id] = old_secret_refs
                service.update(secrets=new_secret_refs)

    def enhance(self, domain, enhancement, options=None):
        # type: (str, str, dict) -> None
        pass

    def supported_enhancements(self):
        # type: () -> List[str]
        return []

    def save(self, title=None, temporary=False):
        # type: (str, bool) -> None
        pass

    def rollback_checkpoints(self, rollback=1):
        # type: (int) -> None
        pass

    def recovery_routine(self):
        # type: () -> None
        """Revert changes to updated services.

        :raises: PluginError if rollback fails.
        """

        failed = []
        for service_id in self.old_secret_refs:
            service = self.docker_client.services.get(service_id)

            try:
                service.update(secrets=self.old_secret_refs[service_id])
            except APIError as e:
                logger.error(
                    "Failed to rollback service: {}: {}"
                    .format(service.name, str(e))
                )
                failed.append(service)

        if len(failed) != 0:
            raise PluginError(
                "Failed to rollback {} services."
                .format(len(failed))
            )

    def config_test(self):
        # type: () -> None
        pass

    def restart(self):
        # type: () -> None
        pass
