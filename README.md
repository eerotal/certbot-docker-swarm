certbot-docker-swarm - Certbot plugin for Docker Swarm Secrets
--------------------------------------------------------------

https://github.com/eerotal/certbot-docker-swarm/workflows/Build%20and%20push%20to%20Docker%20Hub/badge.svg

`certbot-docker-swarm` is a [certbot](https://certbot.eff.org/) installer
plugin that can be used to automatically deploy TLS certificates as Docker
Swarm Secrets. `certbot-docker-swarm` also automatically updates Swarm
services to use the new secrets after renewal.

## Usage

Install `certbot-docker-swarm` by running the following commands:

```
git clone git@github.com:eerotal/certbot-docker-swarm.git
cd certbot-docker-swarm
python3 setup.py install
```

After running these commands, you can verify that the installation
was successful by running `certbot plugins`. This should print a list
of all plugins `certbot` is able to find. One of the plugins listed
should be `docker-swarm`. You can tell `certbot` to use the installer
plugin by passing `-i docker-swarm` when invoking `certbot`. See the
[certbot man page](https://certbot.eff.org/docs/man/certbot.html)
for more info.

## Swarm Secrets

When certificates are renewed `certbot-docker-swarm` creates Docker Swarm
Secrets named with the format

`{domain}_{name}_v{version}`

where

- `{domain}` = The domain the certificate authenticates.
- `{name}` = The name of the secret. One of: cert, key, chain, fullchain.
- `{version}` = The Unix Epoch timestamp of the certificate in seconds.

All generated secrets have a set of labels:

- `certbot.managed` = Always "true".
- `certbot.domain` = The domain the certificate authenticates.
- `certbot.name` = The name of the secret. One of: cert, key, chain, fullchain.
- `certbot.version` = The Unix Epoch timestamp of the certificate in seconds.

These labels are used by `certbot-docker-swarm` for identifying services
which need to be updated after certificate renewal.

## Configuring Swarm Services

If your domain is `example.com`, you can create an `nginx` Swarm service that
uses a certificate managed by `certbot-docker-swarm` by running

```
docker service create \
    --secret source=example.com_cert_v{version},target=example.com_cert \
    --secret source=example.com_key_v{version},target=example.com_key \
    --secret source=example.com_chain_v{version},target=example.com_chain \
    --secret source=example.com_fullchain_v{version},target=example.com_fullchain \
    --name nginx \
    nginx:alpine
```

If your service doesn't need all of the secrets you can omit the
ones that aren't required. Secrets will still be generated from
those files aswell but they won't be attached to your services.

If you deploy your Docker Swarm Services using `docker-compose`
files, you can use a configuration similar to the one below:

```
...
...

version: '3.9'
services:
  nginx
    image: nginx:alpine

    ...
    ...

    secrets:
      - example.com_cert
      - example.com_key
      - example.com_chain
      - example.com_fullchain

secrets:
  example.com_cert:
    name: example.com_cert_v{version}
    external: true
  example.com_key:
    name: example.com_key_v{version}
    external: true
  example.com_chain:
    name: example.com_chain_v{version}
    external: true
  example.com_fullchain:
    name: example.com_fullchain_v{version}
    external: true

...
...

```

## Dependencies

In addition to Docker with Swarm mode enabled you'll need the following
dependencies from PyPI:

- docker >= 4.4
- certbot >= 1.10

These are, however, automatically installed by the `setup.py` script.

## License

`certbot-docker-swarm` is licensed under the BSD 3-clause license. See
the file `LICENSE` for more information.

Copyright Eero Talus 2021
