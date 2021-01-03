import zope.interface
from certbot import interfaces
from certbot.errors import PluginError
from certbot.plugins import common
from typing import List
import docker
from docker.errors import APIError
import time

@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class SwarmInstaller(common.Plugin):
    """Docker Swarm installer."""

    description = "Docker Swarm installer"

    LABEL_PREFIX="certbot"
    SECRET_FORMAT="{domain}_{secret}_v{version}"

    def __init__(self, *args, **kwargs):
        self.docker_client = docker.from_env()
        self.created_secrets = []

    def prepare(self) -> None:
        # No additional preparation is necessary.
        pass

    def more_info(self) -> str:
        """Return a human-readable help string.

        :return: A help string.
        :rtype str:
        """
        return "Docker Swarm installer"

    @staticmethod
    def get_label(label: List[str]) -> str:
        """Get a fully qualified label string.

        :param List[str] label: The label components as a list.

        :return: The label as a string.
        :rtype: str
        """

        tmp = [SwarmInstaller.LABEL_PREFIX]
        tmp.extend(label)
        return ".".join(tmp)

    def secret_from_file(self, domain: str, secret: str, filepath: str) -> None:
        """ Create a Docker Swarm secret from a file.

        :param domain str: The domain the secret authenticates.
        :param secret str: The name of the secret.
        :param sn str: The serial number of the secret.
        :param filepath str: The file path of the secret.
        """


        labels = {}
        labels[SwarmInstaller.get_label(["managed"])] = "true"
        labels[SwarmInstaller.get_label(["domain"])] = domain

        name = SwarmInstaller.SECRET_FORMAT.format(
            domain=domain,
            secret=secret,
            version=int(time.time())
        )

        with open(filepath, "r") as f:
            secret_id = self.docker_client.secrets.create(
                name=name,
                data=f.read(),
                labels=labels
            ).id
            self.created_secrets.append(secret_id)

    def get_all_names(self) -> List[str]:
        """Get all names that have at least one existing certificate secret.

        :rtype: List[str]
        """

        ret = []

        for s in self.docker_client.secrets.list():
            labels = s.attrs.get("Spec").get("Labels")
            if labels.get(SwarmInstaller.get_label(["managed"]), None) != "true":
                continue

            d = labels.get(SwarmInstaller.get_label(["domain"]), None)
            if d is not None and d not in ret:
                ret.append(d)

        return ret

    def deploy_cert(self, domain: str, cert_path: str, key_path: str, chain_path: str, fullchain_path: str) -> None:
        """Create Docker Swarm secrets from certificates.

        :param str domain: Certificate domain.
        :param str cert_path: Path to the certificate file.
        :param str key_path: Path to the private key file.
        :param str chain_path: Path to the certificate chain file.
        :param str fullchain_path: Path to the fullchain file.
        """

        self.secret_from_file(domain, "cert", cert_path)
        self.secret_from_file(domain, "key", key_path)
        self.secret_from_file(domain, "chain", chain_path)
        self.secret_from_file(domain, "fullchain", fullchain_path)

    def enhance(self, domain: str, enhancement: str, options=None) -> None:
        # No enchancements are possible with Docker Swarm secrets.
        raise PluginError("Docker Swarm installer doesn't support enhancements.")

    def supported_enhancements(self) -> List[str]:
        # No enchancements are possible with Docker Swarm secrets.
        return []

    def save(self, title: str=None, temporary: bool=False) -> None:
        pass

    def rollback_checkpoints(self, rollback=1) -> None:
        # Rollbacks should be handled using Docker Swarm service rollbacks.
        raise PluginError("Docker Swarm installer doesn't support rollbacks.")

    def recovery_routine(self) -> None:
        """Revert changes to deployed certificates.

        :raises PluginError: If recovery fails.
        """

        # Remove all newly generated secrets.
        for secret_id in self.created_secrets:
            try:
                self.docker_client.secrets.get(secret_id).remove()
            except APIError:
                raise PluginError(
                    "Failed to remove secret {} during recovery."
                    .format(secret_id)
                )

    def config_test(self) -> None:
        # No configuration checks required.
        pass

    def restart(self) -> None:
        # Docker Swarm services are automatically restarted
        # after deployment so we can just skip this.
        pass
