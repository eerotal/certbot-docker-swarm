import zope.interface
from certbot import interfaces
from certbot.errors import PluginError
from certbot.plugins import common
from typing import List
import docker
from docker.errors import APIError
from docker.types.services import SecretReference
from docker.models.secrets import Secret
import time

@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class SwarmInstaller(common.Plugin):
    """Docker Swarm installer."""

    description = "Docker Swarm installer"

    LABEL_PREFIX="certbot"
    SECRET_FORMAT="{domain}_{name}_v{version}"

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

    def secret_from_file(self, domain: str, name: str, filepath: str) -> None:
        """ Create a Docker Swarm secret from a file.

        :param domain str: The domain the secret authenticates.
        :param name str: The name of the secret.
        :param filepath str: The file path of the secret.
        """

        version=int(time.time())

        labels = {}
        labels[SwarmInstaller.get_label(["managed"])] = "true"
        labels[SwarmInstaller.get_label(["domain"])] = domain
        labels[SwarmInstaller.get_label(["name"])] = name
        labels[SwarmInstaller.get_label(["version"])] = version

        name = SwarmInstaller.SECRET_FORMAT.format(
            domain=domain,
            name=name,
            version=version
        )

        with open(filepath, "r") as f:
            try:
                secret_id = self.docker_client.secrets.create(
                    name=name,
                    data=f.read(),
                    labels=labels
                ).id
            except:
                raise PluginError("Failed to create Docker Secret: {}".format(name))

            self.created_secrets[secret_id] = self.docker_client.secrets.get(secret_id)

    def get_all_names(self) -> List[str]:
        """Get all domain names that have at least one existing certificate secret.

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

    def create_secret_ref(self, secret: Secret) -> SecretReference:
        return SecretReference(
            secret.id,
            secret.name,
            secret.get("File").get("Name"),
            secret.get("File").get("UID"),
            secret.get("File").get("GID"),
            secret.get("File").get("Mode")
        )

    def create_subst_secret_ref(self, domain: str, old: Secret) -> SecretReference:
        for s in self.created_secrets:
            labels = s.attrs.get("Spec").get("Labels")

            if labels.get(SwarmInstaller.get_label(["domain"]), None) != domain:
                continue

            return SecretReference(
                s.id,
                s.name,
                old.get("File").get("Name"),
                old.get("File").get("UID"),
                old.get("File").get("GID"),
                old.get("File").get("Mode")
            )

        raise PluginError("No secret for domain: {}".format(domain))

    def save(self, title: str=None, temporary: bool=False) -> None:
        print("Rotating secrets in Docker Swarm services.")

        services = self.docker_client.services.list()
        for service in services:
            print("Working in service {}".format(service.id))

            secret_refs = []
            secret_conf = s.attrs.get("Spec").get("TaskTemplate").get("ContainerSpec").get("Secrets")

            for tmp in secret_conf:
                secret = self.docker_client.secrets.get(tmp.id)
                labels = secret.attrs.get("Spec").get("Labels")

                if labels.get(SwarmInstaller.get_label(["managed"]), None) != "true":
                    # Add secret to updated service as-is.
                    secret_refs.append(self.create_secret_ref(secret))
                else:
                    # Substitute secret with a new one.
                    print("--> Queueing secret update for {}".format(secret.name))
                    domain = labels.get(SwarmInstaller.get_label(["domain"]))
                    secret_refs.append(
                        self.create_subst_secret_ref(
                            domain,
                            secret
                        )
                    )

            print("--> Committing changes.")
            service.update(secrets=secret_refs)


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
                self.created_secrets[secret_id].remove()
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
