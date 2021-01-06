# certbot-docker-swarm - Certbot for Docker Swarm clusters

`certbot-docker-swarm` is a `certbot` Docker image with suitable configuration and
scripts for running in a Docker Swarm cluster. `certbot-docker-swarm` includes support
for automatic certificate renewal, deploying certificates as Docker Secrets and
automatically rotating secrets in running services.

## Usage

This image can only run on a Docker Swarm manager node. An example Docker Swarm
stack is included in `stack.yml`. In addition to the existing environment
variables, you'll also need to define `CB_EMAIL`, `CB_DOMAINS` and `CB_AGREE_TOS`.
All supported environment variables are described in the table below.

| Variable         | Default | Description                                                |
|------------------|---------|------------------------------------------------------------|
| CB_EMAIL         |         | Let's Encrypt account E-mail.                              |
| CB_DOMAINS       |         | Comma separated list of domains.                           |
| CB_AGREE_TOS     | n       | y/n to agree/disagree to the Let's Encrypt TOS.            |
| CB_EFF_EMAIL     | n       | y/n to allow Let's Encrypt to give your E-mail to the EFF. |
| CB_STAGING       | n       | y/n to enable/disable using Let's Encrypt staging servers. |
| CB_AUTO_DEPLOY   | n       | y/n to enable/disable Docker Secret auto rotation.         |
| CB_CERTONLY_ARGS |         | Extra arguments to `certbot certonly`.                     |
| CB_RENEW_ARGS    |         | Extart arguments to `certbot renew`.                       |

Some important paths in the container are described in the table below.

| Path                 | Description                                                            |
|----------------------|------------------------------------------------------------------------|
| /etc/letsencrypt/    | Certbot directory containing certificates among other things. (1)      |
| /root/conf           | Configuration directory containing cert associations for services. (2) |
| /var/run/docker.sock | Docker socket required for managing Docker secrets etc. (3)            |

(1) You should mount a volume at `/etc/letsencrypt` to preserve certificates and
Let's Encrypt account details across container updates.

(2) You should mount `/root/conf` for example at `/etc/certbot-docker-swarm` on the
cluster manager node. Note that you need to manually create the `/etc/certbot-docker-swarm`
directory before deploying the cluster as the Swarm orchestrator won't generate it
automatically. This directory contains up-to-date secret associations for all
managed services and a script for generating a YAML file containing the secrets
for each service. This is useful if you deploy your Swarm stack using a docker-compose
file which contains the initial configuration for secrets. When `certbot-docker-swarm`
updates the services with new secrets, you won't be able to deploy a working service
using the (now outdated) secret configuration. You can instead generate an extension
YAML file using the script `/etc/swam-certbot/generate-secret-yml.sh` and pass
that along with the original stack to `docker stack deploy` using the `-c` flag.

You can run `generate-secret-yml.sh` like this:

```
cd [Docker Swarm stack directory]
sh /etc/certbot-docker-swarm/generate-secret-yml.sh [stack name] [original stack.yml]
```

This generates a file named `secrets.yml` in the current directory.


(3) You must mount the Docker socker from the Swarm manager node into the container
at `/var/run/docker.sock`. Otherwiser the container can't manage the Swarm cluster.

## License

This project is licensed under the BSD 3-clause license. See the file `LICENSE.md`
for more information.

Copyright Eero Talus 2020
