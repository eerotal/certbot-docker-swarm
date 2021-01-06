#
# A Python script for dumping the current secret configuration of a
# Docker Swarm stack as a Docker Compose YAML file.
#

import sys
import docker
from docker.models.services import Service
import yaml
from argparse import ArgumentParser
from typing import Union, Dict

def get_secrets(service: Service) -> dict:
    """
    Get the secret configuration of a service in the docker-compose YAML format.

    :param service: Service, The Docker service to use.

    :return: The configuration as a dictionary.
    :rtype: dict
    """

    ret = {}

    secrets = service.attrs["Spec"]["TaskTemplate"]["ContainerSpec"]["Secrets"]
    for s in secrets:
        ret[s["File"]["Name"]] = {
            "name": s["SecretName"],
            "external": True
        }

    return ret

def main(
        stack_name: str,
        compose_version: Union[str, None]=None,
        outfile: Union[str, None]=None
) -> None:
    """
    Dump secret configuration of a stack as docker-compose YAML.

    :param stack_name: str, None, The stack name to use.
    :param compose_version: str, None, Optional compose file version to use.
    :param outfile: str, None: An optional output file.
    """

    client = docker.from_env()
    services = client.services.list()

    secrets = {}

    # Loop over all services in the specified stack and merge secrets
    # into the 'secrets' dictionary.
    for s in services:
        labels = client.services.list()[0].attrs["Spec"]["Labels"]
        if "com.docker.stack.namespace" in labels:
            if labels["com.docker.stack.namespace"] == stack_name:
                tmp = get_secrets(s)

                if not set(secrets).intersection(tmp):
                    secrets.update(tmp)
                else:
                    print("[ERROR] Some services have conflicting keys.")
                    return 1

    compose_spec = {"secrets": secrets}

    # Add version information if provided by user.
    if compose_version is not None:
        compose_spec["version"] = compose_version

    if outfile is not None:
        # Write YAML to the file specified by the user.
        with open(outfile, "w") as f:
            f.write(yaml.dump(compose_spec))
    else:
        # Dump YAML to STDOUT.
        print(yaml.dump(compose_spec))

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument(
        "stack",
        help="The Docker Swarm stack to use."
    )
    ap.add_argument(
        "--compose-version",
        "-c",
        default=None,
        help="Compose file version. If not specified, no version is added to output."
    )
    ap.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write to a file instead of STDOUT."
    )
    args = ap.parse_args()

    sys.exit(main(args.stack, args.compose_version, args.output))
