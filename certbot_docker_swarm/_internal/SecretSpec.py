import json

from .utils import SwarmInstallerUtils

class SecretSpec():
    def __init__(self, docker_client):
        # type: (DockerClient) -> None
        """
        Container class for storing SecretReferences.

        :param DockerClient docker_client: A DockerClient instance.
        """

        self.docker_client = docker_client
        self.spec = {}

    @property
    def services(self):
        """Get the SecretReferences for all Services.

        :return: A dict with Service <-> SecretReference associations.
        :rtype: Dict[str, Dict[str, SecretReference]]
        """
        return self.spec

    def add_ref(self, service_id, ref):
        # type: (str, SecretReference) -> None
        """Add a SecretReference to a Service.

        If a SecretReference for a Secret with the same filename (target)
        already exists in the SecretSpec, the versions of the Secrets are
        compared. The newer of the SecretReferences is retained in/added to
        the SecretSpec.

        :param str service_id: The Service ID.
        :param dict SecretReference: The SecretReference.
        """

        if service_id not in self.spec:
            self.spec[service_id] = {}

        for secret_id in self.spec[service_id]:
            old_name = self.spec[service_id][secret_id].get("File").get("Name")
            new_name = ref.get("File").get("Name")

            if old_name == new_name:
                old = self.docker_client.secret.get(secret_id)
                new = self.docker_client.secret.get(ref.get("SecretID"))
                old_version = SwarmInstallerUtils.get_secret_version(old)
                new_version = SwarmInstallerUtils.get_secret_version(new)

                if new_version <= old_version:
                    # Skip SecretReference if it's older than the current
                    # one in the SecretSpec.
                    return

        # Assign the SecretReferences to a dict to prevent multiple
        # references for the same Secret.
        self.spec[service_id][ref.get("SecretID")] = ref

    def get_refs(self, service_id):
        # type: (str) -> List[SecretReference]
        """ Get SecretReferences of a Service in a list.

        :return: A list of SecretReferences.
        :rtype: List[SecretReference]
        """

        return list(self.spec.get(service_id).values())

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
