# certbot-docker-swarm - Docker images

`certbot-docker-swarm` has Docker images on Docker Hub. The images are based on
a tiny Alpine Linux base image with only `certbot`, `certbot-docker-swarm` and
dependencies installed. The Docker images are built so that they can be configured
by setting various environment variables via Docker's builtin mechanisms.

You can find the Docker images on Docker Hub at
[eerotal/certbot-docker-swarm](https://hub.docker.com/repository/docker/eerotal/certbot-docker-swarm).

## Usage

### Entrypoint commands

You can pass the Docker container a few arguments to perform different tasks
using `docker exec`. All of the implemented arguments are described in the table below.

| Command       | Description                                                    |
|---------------|----------------------------------------------------------------|
|               | Run the automatic certificate acquisition and renewal process. |
| `shell`       | Start an interactive shell in the container.                   |
| `dump-config` | Dump secret configuration of an existing Docker Swarm stack.   |

`dump-config` can be used to dump the secret configuration of an existing Docker
Swarm stack as a docker-compose file. This is useful if you want to update a
Swarm stack but you still want to keep the secret configuration of the stack. The
docker-compose file is printed to stdout by default but you can redirect the
contents to a file and pass the file to `docker stack deploy` using the `-c`
flag. Pass `dump-config --help` to the container for more information. Note that
you'll need to figure out the ID of the `certbot-docker-swarm` container using
`docker ps` because you can't use `docker exec` on a Swarm service directly.

### Environment variables

The Docker image can only run on a Docker Swarm manager node. Attempting to run it
anywhere else will result in an error. An example Docker Swarm stack is included in
`stack.yml`. In addition to the existing environment variables, you'll also need to
define `CB_EMAIL`, `CB_DOMAINS` and `CB_AGREE_TOS` All supported environment variables
are described in the table below.

| Variable           | Default | Description                                                   |
|--------------------|---------|---------------------------------------------------------------|
| `CB_EMAIL`         |         | ACME server E-mail address.                                   |
| `CB_DOMAINS`       |         | Comma separated list of domains.                              |
| `CB_AGREE_TOS`     | n       | y/n to agree/disagree to the ACME server's TOS. (*1)          |
| `CB_EFF_EMAIL`     | n       | y/n to allow/disallow certbot to give your E-mail to the EFF. |
| `CB_STAGING`       | n       | y/n to enable/disable use of staging ACME servers.            |
| `CB_AUTO_DEPLOY`   | n       | y/n to enable/disable automatic Docker Secret deployment.     |
| `CB_CERTONLY_ARGS` |         | Extra CLI arguments to `certbot certonly`.                    |
| `CB_RENEW_ARGS`    |         | Extra CLI arguments to `certbot renew`.                       |

Notes:

1. Agreeing to the ACME server's TOS is mandatory if you want to use its services
   but you must still explicitly define the `CB_AGREE_TOS` variable.

By default `certbot` acquires certificates from Let's Encrypt but you can use other
ACME servers by passing additional arguments in `CB_CERTONLY_ARGS` and `CB_RENEW_ARGS`.

### Container paths

Some important paths in the container are described in the table below.

| Path                   | Description                                                         |
|------------------------|---------------------------------------------------------------------|
| `/etc/letsencrypt/`    | Certbot directory containing certificates among other things. (*1)  |
| `/var/run/docker.sock` | Docker socket required for managing Docker secrets etc. (*2)        |

Notes:

1. You should mount a volume at `/etc/letsencrypt` to preserve certificates and
   Let's Encrypt account configuration across container updates.
2. You must mount the Docker socket from the Swarm manager node into the container
   at `/var/run/docker.sock`. Otherwiser the container can't manage the Swarm cluster.
