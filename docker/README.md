# certbot-docker-swarm - Docker images

*certbot-docker-swarm* has Docker images on Docker Hub. The images are based on
a tiny Alpine Linux base image with only *certbot*, *certbot-docker-swarm* and
dependencies installed. The Docker images are built so that they can be configured
by setting various environment variables via Docker's builtin mechanisms.

You can find the Docker images on Docker Hub at
[eerotal/certbot-docker-swarm](https://hub.docker.com/repository/docker/eerotal/certbot-docker-swarm).

## Usage

### Environment variables

The Docker image can only run on a Docker Swarm manager node. Attempting to run it
anywhere else will result in an error. An example Docker Swarm stack is included in
`stack.yml`. In addition to the existing environment variables, you'll also need to
define `CB_EMAIL`, `CB_DOMAINS` and `CB_AGREE_TOS` All supported environment variables
are described in the table below.

| Variable           | Default   | Description                                                   |
|--------------------|-----------|---------------------------------------------------------------|
| `CB_EMAIL`         |           | ACME server E-mail address.                                   |
| `CB_DOMAINS`       |           | Comma separated list of domains.                              |
| `CB_AGREE_TOS`     | n         | y/n to agree/disagree to the ACME server's TOS. (*1)          |
| `CB_EFF_EMAIL`     | n         | y/n to allow/disallow certbot to give your E-mail to the EFF. |
| `CB_STAGING`       | n         | y/n to enable/disable use of staging ACME servers.            |
| `CB_AUTO_DEPLOY`   | n         | y/n to enable/disable automatic Docker Secret deployment.     |
| `CB_RUN_ARGS`      |           | Extra CLI arguments to `certbot run`.                         |
| `CB_RENEW_ARGS`    |           | Extra CLI arguments to `certbot renew`.                       |
| `CB_CRON_EXPR`     | 0 6 * * * | Cron expression for renewing certificates.                    |

Notes:

1. Agreeing to the ACME server's TOS is mandatory if you want to use its services
   but you must still explicitly define the `CB_AGREE_TOS` variable.

By default *certbot* acquires certificates from Let's Encrypt but you can use other
ACME servers by passing additional arguments in `CB_RUN_ARGS` and `CB_RENEW_ARGS`.

### Container paths

Some important paths in the container are described in the table below.

| Path                   | Description                                                         |
|------------------------|---------------------------------------------------------------------|
| `/etc/letsencrypt/`    | Certbot directory containing certificates among other things. (*1)  |
| `/var/run/docker.sock` | Docker socket required for managing Docker secrets etc. (*2)        |

Notes:

1. You should mount a volume at `/etc/letsencrypt` to preserve certificates and
   ACME server account configuration across container updates.
2. You must mount the Docker socket from the Swarm manager node into the container
   at `/var/run/docker.sock`. Otherwiser the container can't manage the Swarm cluster.

### Service bootstrap

For services to be updated with renewed TLS certificates, they need to contain
an initial secret which *certbot-docker-swarm* recognizes as a TLS secret. When
deploying new Swarm services, you have two options for configuring initial
secrets.

1. You can create initial dummy secrets before deploying *certbot-docker-swarm*
   which contain self-signed certificate files. These secrets must have the
   correct values for the labels described in the main README.
2. You can deploy *certbot-docker-swarm* first and manually add the initial
   (real) secrets to other services before deploying them.

### Using certbot-docker-swarm with Swarm Stacks

When *certbot-docker-swarm* manages certificates for a Swarm service, the
service configuration is automatically updated when new certificates are
issued. This causes problems if you need to update your stack deployed from
a docker-compose file as the original configuration still contains references
to the initial certificates. However, the *certbot-docker-swarm* container
contains a solution to this problem: `dump-config`. `dump-config` is a Python0
script which you can execute by running

`docker exec CONTAINER_ID dump-config ARGS`

where

- `CONTAINER_ID` is the ID of the *certbot-docker-swarm* container.
- `ARGS` are CLI arguments passed to `dump-config`.

`dump-config` takes as it's argument an existing stack name and dumps the
current secret configuration for the stack as docker-compose YAML to stdout
(default) or to a file. You can the pass this generated file to `docker stack
deploy` along with your original stack definition to specify the correct
secrets during stack updates. Note that you need to find out the ID of the
*certbot-docker-swarm* container first because you can't directly execute
commands in Docker Swarm services. Pass `--help` to `dump-config` for more
information.
