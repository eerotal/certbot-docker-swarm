"""Class for managins SecretReferences in Swarm stacks."""

import json
import logging

from docker.types.services import SecretReference

from certbot_docker_swarm._internal.util.secretutils import SecretUtils

logger = logging.getLogger(__name__)


class SecretSpec():
    """Class for managins SecretReferences in Swarm stacks."""

    def __init__(self, docker_client, spec=None):
        # type: (DockerClient) -> None
        """
        Container class for storing SecretReferences.

        :param DockerClient docker_client: A DockerClient instance.
        """

        self.docker_client = docker_client

        if spec is None:
            self.spec = {}
            self.from_swarm()
        else:
            self.spec = spec

    @property
    def services(self):
        """Get the SecretReferences for all Services.

        :return: A dict with Service <-> SecretReference associations.
        :rtype: Dict[str, Dict[str, SecretReference]]
        """

        return self.spec

    def from_swarm(self):
        # type: () -> None
        """Load a SecretSpec from the current Docker Swarm."""

        for service in self.docker_client.services.list():
            secrets = service.attrs.get("Spec") \
                                   .get("TaskTemplate") \
                                   .get("ContainerSpec") \
                                   .get("Secrets", None)

            if secrets is not None:
                for secret in secrets:
                    self.set_ref(
                        service.attrs.get("ID"),
                        SecretReference(
                            secret.get("SecretID"),
                            secret.get("SecretName"),
                            secret.get("File").get("Name"),
                            secret.get("File").get("UID"),
                            secret.get("File").get("GID"),
                            secret.get("File").get("Mode")
                        )
                    )

    def set_ref(self, service_id, ref):
        # type: (str, SecretReference) -> None
        """Add a SecretReference to a Service.

        :param str service_id: The Service ID.
        :param dict SecretReference: The SecretReference.
        """

        if service_id not in self.spec:
            self.spec[service_id] = {}

        # Assign the SecretReferences to a dict to prevent multiple
        # references for the same Secret.
        self.spec[service_id][ref.get("SecretID")] = ref

    def rm_ref(self, service_id, secret_id):
        """Remove a SecretReference from a SecretSpec.

        :param str service_id: The Service ID.
        :param str secret_id: The Secret ID.
        """
        del self.spec[service_id][secret_id]

    def get_refs(self, service_id):
        # type: (str) -> List[SecretReference]
        """ Get SecretReferences of a Service in a list.

        :return: A list of SecretReferences.
        :rtype: List[SecretReference]
        """

        return list(self.spec.get(service_id).values())

    def update_refs(self, candidate):
        # type: (Secret, Secret, Secret, Secret) -> None
        """Update SecretReferences of all Services to use a new Secret.

        :param Secret candidate: The new Secret.
        """

        logger.info("Updating Docker Swarm Services.")
        for service_id in self.services:
            service = self.docker_client.services.get(service_id)
            logger.info("Service %s (id: %s)", service.name, service.id)

            for old in self.get_refs(service_id):
                new = self.get_updated_ref(old, candidate)
                if new != old:
                    self.set_ref(service_id, new)
                    self.rm_ref(service_id, old.get("SecretID"))

    def get_updated_ref(self, ref, candidate):
        # type: (SecretReference, Secret) -> None
        """Attempt to renew a SecretReference with a Secret.

        :param SecretReference ref: The old SecretReference.
        :param Secret candidate: The new Secret candidate.

        :return: A new SecretReference or 'old' if renewal was not possible.
        :rtype: SecretReference
        """

        old = self.docker_client.secrets.get(ref.get("SecretID"))
        if SecretUtils.secret_renews(old, candidate):
            logger.info(
                "--> Update %s: %s -> %s",
                ref.get("File").get("Name"),
                old.name,
                candidate.name
            )
            return SecretReference(
                candidate.id,
                candidate.name,
                ref.get("File").get("Name"),
                ref.get("File").get("UID"),
                ref.get("File").get("GID"),
                ref.get("File").get("Mode")
            )

        return ref

    def write(self, filepath):
        # type: (str) -> None
        """Write the SecretSpec to a file.

        :param str filepath: The output file path.
        """

        with open(filepath, "w") as f:
            json.dump(self.spec, f)

    def read(self, filepath):
        # type: (str) -> None
        """Load the SecretSpec from a file.

        :param str filepath: The input file path.
        """

        self.spec.clear()
        with open(filepath, "r") as f:
            self.spec.update(json.load(f))
