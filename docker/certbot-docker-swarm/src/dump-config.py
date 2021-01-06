#/usr/bin/env python3

#
# A Python script for dumping the current secret configuration of a
# Docker Swarm stack as a Docker Compose YAML file.
#

import sys
import docker
from docker.models.services import Service
import yaml
from argparse import ArgumentParser
from typing import Optional, Dict

import logging
logger = logging.getLogger(__name__)

def get_secrets(service: Service) -> dict:
    """Get the secret configuration of a service as docker-compose YAML.

    :param Service service: The Docker service to use.

    :return: The configuration as a dictionary.
    :rtype: dict
    """

    ret = {}
    secrets = service.attrs.get("Spec") \
                           .get("TaskTemplate") \
                           .get("ContainerSpec") \
                           .get("Secrets")

    if secrets is None:
        return {}

    for s in secrets:
        ret[s.get("File").get("Name")] = {
            "name": s.get("SecretName"),
            "external": True
        }

    return ret

def do_secrets_conflict(a: dict, b: dict) -> bool:
    """Check whether secrets in two dicts returned by get_secrets() conflict.

    :return: True if secrets conflict, False otherwise.
    :rtype: bool
    """

    for key in a:
        if key in b and a[key]["name"] != b[key]["name"]:
            return True

    return False

def main(
    stack_name: str,
    compose_version: Optional[str]=None,
    outfile: Optional[str]=None
) -> None:
    """Dump secret configuration of a stack as docker-compose YAML.

    :param str stack_name: The stack name to use.
    :param Optional[str] compose_version: Compose file version to use.
    :param Optional[str] outfile: Output file. None = stdout.
    """

    client = docker.from_env()
    services = client.services.list()

    stack_found = False
    secrets = {}

    # Loop over all services in the specified stack and merge secrets
    # into the 'secrets' dictionary.
    for s in services:
        labels = s.attrs.get("Spec").get("Labels")
        if labels.get("com.docker.stack.namespace", None) == stack_name:
            stack_found = True
            tmp = get_secrets(s)
            if not do_secrets_conflict(secrets, tmp):
                secrets.update(tmp)
            else:
                logger.error("Some services have conflicting secrets.")
                return 1

    if not stack_found:
        logger.error("No such stack: {}".format(stack_name))
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
        help="Compose file version. If not specified, no version is added."
    )
    ap.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write to a file instead of STDOUT."
    )
    args = ap.parse_args()

    sys.exit(main(args.stack, args.compose_version, args.output))
