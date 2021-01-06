"""Docker Swarm installer"""

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

    description = "Docker Swarm Installer"

    L_PREFIX = "certbot"
    L_MANAGED = L_PREFIX + ".managed"
    L_VERSION = L_PREFIX + ".version"
    L_DOMAIN = L_PREFIX + ".domain"
    L_NAME = L_PREFIX + ".name"

    SECRET_FORMAT="{domain}_{name}_v{version}"

    def __init__(self, *args, **kwargs):
        self.docker_client = docker.from_env()
        self.renewed_secrets = {}
        self.old_secret_refs = {}

        # Use the Docker task retention limit as the number of old
        # secrets to keep. This makes sure enough secrets for historic
        # tasks are always kept in the Swarm.
        info = self.docker_client.info()
        self.keep_secrets = info.get("Swarm") \
                                .get("Cluster") \
                                .get("Spec") \
                                .get("Orchestration") \
                                .get("TaskHistoryRetentionLimit")

        super().__init__(*args, **kwargs)

    def prepare(self) -> None:
        # No additional preparation is necessary.
        pass

    def more_info(self) -> str:
        """Return a human-readable help string.

        :return: A help string.
        :rtype str:
        """

        return "Installs certificates as Docker Swarm Secrets and " \
               "automatically updates Docker Swarm Services to use" \
               "the renewed secrets."

    def secret_from_file(self, domain: str, name: str, filepath: str) -> None:
        """ Create a Docker Swarm secret from a certificate file.

        :param domain str: The domain the secret authenticates.
        :param name str: The name of the secret.
        :param filepath str: The file path of the secret.
        """

        version=int(time.time())

        labels = {}
        labels[SwarmInstaller.L_MANAGED] = "true"
        labels[SwarmInstaller.L_DOMAIN] = domain
        labels[SwarmInstaller.L_NAME] = name
        labels[SwarmInstaller.L_VERSION] = str(version)

        name = SwarmInstaller.SECRET_FORMAT.format(
            domain=domain,
            name=name,
            version=version
        )

        with open(filepath, "r") as f:
            try:
                sid = self.docker_client.secrets.create(
                    name=name,
                    data=f.read(),
                    labels=labels
                ).id
            except APIError as e:
                raise PluginError(
                    "Failed to create Docker Secret {}: {}"
                    .format(name, str(e))
                ) from e

            self.renewed_secrets[sid] = self.docker_client.secrets.get(sid)

    def get_all_names(self) -> List[str]:
        """Get all domain names that have at least one existing secret.

        :rtype: List[str]
        """

        ret = []

        for s in self.docker_client.secrets.list():
            labels = s.attrs.get("Spec").get("Labels")
            if labels.get(SwarmInstaller.L_MANAGED, None) != "true":
                continue

            d = labels.get(SwarmInstaller.L_DOMAIN, None)
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

        self.update_services()
        self.rm_old_secrets_by_domain(domain)

    def get_secrets_by_domain_and_name(
            self, domain: str,
            name: str
    ) -> List[Secret]:
        """Get all secrets of a specific type for a domain.

        :param str domain: The domain whose secrets to get.
        :param str name: The name of the secrets to get.

        :return: A list of secrets.
        :rtype: List[Secret]
        """

        ret = []
        secrets = self.docker_client.secrets.list()

        for secret in secrets:
            labels = secret.attrs.get("Spec").get("Labels")
            if labels.get(SwarmInstaller.L_MANAGED, None) != "true":
                continue
            if labels.get(SwarmInstaller.L_DOMAIN, None) != domain:
                continue
            if labels.get(SwarmInstaller.L_NAME, None) != name:
                continue
            ret.append(secret)

        return ret

    def rm_old_secrets_by_domain_and_name(
            self,
            domain: str,
            name: str,
            keep: int
    ) -> int:
        """Remove oldest secrets of a specific type for a specific domain.

        :param str domain: The domain whose secrets to remove.
        :param str name: The secret name to remove, eg. cert, key, ...
        :param keep int: How many secrets to keep.

        :return: The number of secrets removed.
        :rtype: int
        """

        remove = sorted(
            self.get_secrets_by_domain_and_name(domain, name),
            key=lambda x: int(
                x.attrs \
                .get("Spec") \
                .get("Labels") \
                .get(SwarmInstaller.L_VERSION) \
            ),
            reverse=True
        )[keep:]

        n = len(remove)

        for secret in remove:
            try:
                secret.remove()
            except APIError as e:
                print(
                    "Failed to remove secret {} (id: {}): {}"
                    .format(secret.name, secret.id, str(e))
                )
                n -= 1

            print("Removed secret {} (id: {})".format(secret.name, secret.id))

        return n

    def rm_old_secrets_by_domain(self, domain: str) -> None:
        """Remove oldest secrets for a domain.

        self.keep_secrets number of newest secrets are kept.

        :param str domain: The domain whose secrets to remove.
        """

        n = 0

        print("Removing old secrets.")

        n += self.rm_old_secrets_by_domain_and_name(
            domain,
            "cert",
            self.keep_secrets
        )
        n += self.rm_old_secrets_by_domain_and_name(
            domain,
            "key",
            self.keep_secrets
        )
        n += self.rm_old_secrets_by_domain_and_name(
            domain,
            "chain",
            self.keep_secrets
        )
        n += self.rm_old_secrets_by_domain_and_name(
            domain,
            "fullchain",
            self.keep_secrets
        )

        print("Removed {} secrets.".format(n))

    def update_services(self) -> None:
        """Update Docker Swarm Services to use renewed secrets."""

        print("Updating Docker Swarm Services.")

        for service in self.docker_client.services.list():
            print(
                "Working in service {} (id: {})"
                .format(service.name, service.id)
            )

            dirty = False
            secret_refs = []
            old_secret_refs = []
            secret_conf = service.attrs.get("Spec")\
                                       .get("TaskTemplate")\
                                       .get("ContainerSpec")\
                                       .get("Secrets")

            if secret_conf is None:
                # Skip services with no secrets.
                continue

            for tmp in secret_conf:
                secret = self.docker_client.secrets.get(tmp.get("SecretID"))
                labels = secret.attrs.get("Spec").get("Labels")

                # Get the renewed secret corresponding to the
                # old secret defined in the service spec.
                managed = labels.get(SwarmInstaller.L_MANAGED, None)
                domain = labels.get(SwarmInstaller.L_DOMAIN, None)
                name = labels.get(SwarmInstaller.L_NAME, None)
                renewed_secret = self.get_renewed_secret(domain, name)

                update_id = None
                update_name = None

                if managed != "true" or renewed_secret is None:
                    # Add non-managed and non-renewed secrets as-is.
                    update_id = tmp.get("SecretID")
                    update_name = tmp.get("SecretName")
                else:
                    # Substitute managed secrets with renewed ones.
                    print(
                        "--> Update {}"
                        .format(tmp.get("File").get("Name"))
                    )
                    print(
                        "----> from {} (id: {})"
                        .format(tmp.get("SecretName"), tmp.get("SecretID"))
                    )
                    print(
                        "----> to {} (id: {})"
                        .format(renewed_secret.name, renewed_secret.id)
                    )

                    update_id = renewed_secret.id
                    update_name = renewed_secret.name
                    dirty = True

                # Store old SecretReference.
                old_secret_refs.append(SecretReference(
                    tmp.get("SecretID"),
                    tmp.get("SecretName"),
                    tmp.get("File").get("Name"),
                    tmp.get("File").get("UID"),
                    tmp.get("File").get("GID"),
                    tmp.get("File").get("Mode")
                ))

                # Create new SecretReference.
                secret_refs.append(SecretReference(
                    update_id,
                    update_name,
                    tmp.get("File").get("Name"),
                    tmp.get("File").get("UID"),
                    tmp.get("File").get("GID"),
                    tmp.get("File").get("Mode")
                ))

            if dirty:
                print("--> Committing changes.")
                self.old_secret_refs[service.id] = old_secret_refs
                service.update(secrets=secret_refs)

    def enhance(self, domain: str, enhancement: str, options=None) -> None:
        pass

    def supported_enhancements(self) -> List[str]:
        return []

    def get_renewed_secret(self, domain: str, name: str) -> Optional[Secret]:
        """Get a renewed secret by domain and name.

        :param str domain: The domain name the secret authenticates.
        :param str name: The name of the underlying secret, eg. chain, key, ...

        :return: The Secret object or None if not found.
        :rtype: Optional[Secret]
        """

        for secret_id in self.renewed_secrets:
            secret = self.renewed_secrets[secret_id]
            labels = secret.attrs.get("Spec").get("Labels")

            if labels.get(SwarmInstaller.L_DOMAIN, None) != domain:
                continue
            if labels.get(SwarmInstaller.L_NAME, None) != name:
                continue

            return secret

        return None

    def save(self, title: str=None, temporary: bool=False) -> None:
        pass

    def rollback_checkpoints(self, rollback=1) -> None:
        pass

    def recovery_routine(self) -> None:
        """Revert changes to updated services."""

        failed = []
        for service_id in self.old_secret_refs:
            service = self.docker_client.services.get(service_id)

            try:
                service.update(secrets=self.old_secret_refs[service_id])
            except APIError as e:
                print(
                    "Failed to rollback service: {}: {}"
                    .format(service.name, str(e))
                )
                failed.append(service)

        if len(failed) != 0:
            raise PluginError(
                "Failed to rollback {} services."
                .format(len(failed))
            )

    def config_test(self) -> None:
        pass

    def restart(self) -> None:
        pass
