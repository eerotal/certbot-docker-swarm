import zope.interface
from certbot import interfaces
from certbot.errors import PluginError
from certbot.plugins import common
from typing import List, Optional
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
        self.renewed_secrets = {}
        self.old_secret_refs = {}

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
        """Get a label string prefixed with SwarmInstaller.LABEL_PREFIX.

        :param List[str] label: The label components as a list.

        :return: The label as a string.
        :rtype: str
        """

        tmp = [SwarmInstaller.LABEL_PREFIX]
        tmp.extend(label)
        return ".".join(tmp)

    def secret_from_file(self, domain: str, name: str, filepath: str) -> None:
        """ Create a Docker Swarm secret from a certificate file.

        :param domain str: The domain the secret authenticates.
        :param name str: The name of the secret.
        :param filepath str: The file path of the secret.
        """

        version=int(time.time())

        labels = {}
        labels[SwarmInstaller.get_label(["managed"])] = "true"
        labels[SwarmInstaller.get_label(["domain"])] = domain
        labels[SwarmInstaller.get_label(["name"])] = name
        labels[SwarmInstaller.get_label(["version"])] = str(version)

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
                raise PluginError(
                    "Failed to create Docker Secret: {}"
                    .format(name)
                )

            self.renewed_secrets[secret_id] = self.docker_client.secrets.get(secret_id)

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

    def deploy_cert(
            self,
            domain: str,
            cert_path: str,
            key_path: str,
            chain_path: str,
            fullchain_path: str
    ) -> None:
        """Create Docker Swarm Secrets from certificates.

        :param str domain: Certificate domain.
        :param str cert_path: Path to the certificate file.
        :param str key_path: Path to the private key file.
        :param str chain_path: Path to the certificate chain file.
        :param str fullchain_path: Path to the fullchain file.
        """

        print("Deploying certificates as Docker Secrets.")
        self.secret_from_file(domain, "cert", cert_path)
        self.secret_from_file(domain, "key", key_path)
        self.secret_from_file(domain, "chain", chain_path)
        self.secret_from_file(domain, "fullchain", fullchain_path)

    def enhance(self, domain: str, enhancement: str, options=None) -> None:
        raise PluginError("Docker Swarm installer doesn't support enhancements.")

    def supported_enhancements(self) -> List[str]:
        return []

    def get_renewed_secret(self, domain: str, name: str) -> Optional[Secret]:
        """Get a renewed secret by domain and name.

        :param str domain: The domain name the secret authenticates.
        :param str name: The name of the underlying secret, eg. chain, key, ...

        :return: The Secret object or None if not found.
        :rtype: Optional[Secret]
        """

        for s in self.renewed_secrets:
            labels = s.attrs.get("Spec").get("Labels")

            if labels.get(SwarmInstaller.get_label(["domain"]), None) != domain:
                continue
            if labels.get(SwarmInstaller.get_label(["name"]), None) != name:
                continue

            return s

        return None

    def save(self, title: str=None, temporary: bool=False) -> None:
        if title:
            raise PluginError("Checkpoints not supported by Docker Swarm installer.")
        if temporary:
            raise PluginError("Temporary save not supported by Docker Swarm installer.")

        print("Rotating secrets in Docker Swarm services.")

        for service in self.docker_client.services.list():
            print("Working in Swarm service {}".format(service.id))

            dirty = False
            secret_refs = []
            old_secret_refs = []
            secret_conf = service.attrs.get("Spec").get("TaskTemplate").get("ContainerSpec").get("Secrets")

            if secret_conf is None:
                # Skip services with no secrets.
                continue

            for tmp in secret_conf:
                secret = self.docker_client.secrets.get(tmp.get("SecretID"))
                labels = secret.attrs.get("Spec").get("Labels")

                managed = labels.get(SwarmInstaller.get_label(["managed"]), None)
                domain = labels.get(SwarmInstaller.get_label(["domain"]), None)
                name = labels.get(SwarmInstaller.get_label(["name"]), None)
                renewed_secret = self.get_renewed_secret(domain, name)

                update_secret_id = None
                update_secret_name = None

                if managed != "true" or renewed_secret is None:
                    # Add non-managed and non-renewed secrets to the service as-is.
                    update_secret_id = tmp.get("SecretID")
                    update_secret_name = tmp.get("SecretName")
                else:
                    # Substitute managed secrets with renewed ones.
                    print("--> Queueing secret update for {}".format(secret.name))
                    update_secret_id = renewed_secret.id
                    update_secret_name = renewed_secret.name
                    dirty = True

                # Store old SecretReferences.
                old_secret_refs.append(SecretReference(
                    tmp.get("SecretID"),
                    tmp.get("SecretName"),
                    tmp.get("File").get("Name"),
                    tmp.get("File").get("UID"),
                    tmp.get("File").get("GID"),
                    tmp.get("File").get("Mode")
                ))

                # Create new SecretReferences.
                secret_refs.append(SecretReference(
                    update_secret_id,
                    update_secret_name,
                    tmp.get("File").get("Name"),
                    tmp.get("File").get("UID"),
                    tmp.get("File").get("GID"),
                    tmp.get("File").get("Mode")
                ))

            if dirty:
                print("--> Committing changes.")

                 # Store old secret refs in case changes need to be reverted.
                self.old_secret_refs[service.id] = old_secret_refs

                # Update service.
                service.update(secrets=secret_refs)


    def rollback_checkpoints(self, rollback=1) -> None:
        raise PluginError("Docker Swarm installer doesn't support rollbacks.")

    def recovery_routine(self) -> None:
        """Revert changes to updated services.

        :raises PluginError: If recovery fails.
        """

        # Attempt to rollback service changes.
        revert_failed = False
        for service_id in self.old_secret_refs:
            service = self.docker_client.services.get(service_id)
            try:
                service.update(secrets=self.old_secret_refs[service_id])
            except APIError:
                revert_failed = True

        if revert_failed:
            print("Rollback failed for some services.")

    def config_test(self) -> None:
        # No configuration checks required.
        pass

    def restart(self) -> None:
        # Docker Swarm services are automatically restarted
        # after deployment so we can just skip this.
        pass
