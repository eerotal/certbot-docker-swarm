FROM alpine:3

ENV CB_EMAIL=""
ENV CB_DOMAINS=""
ENV CB_AGREE_TOS="n"
ENV CB_EFF_EMAIL="n"
ENV CB_STAGING="n"
ENV CB_AUTO_DEPLOY="n"
ENV CB_RUN_ARGS=""
ENV CB_CRON_EXPR="0 6 * * *"

USER root
WORKDIR /root

RUN apk add --no-cache \
        certbot \
        docker-py \
        py3-yaml \
        py3-openssl && \
    apk add --no-cache --virtual py3-build-deps \
        git \
        py3-setuptools \
        py3-pip && \
    git clone https://github.com/eerotal/certbot-docker-swarm.git && \
    cd certbot-docker-swarm && \
    python3 setup.py sdist && \
    pip3 install dist/certbot-docker-swarm* && \
    cd .. && \
    rm -rf certbot-docker-swarm && \
    apk del --purge py3-build-deps

COPY docker-entrypoint.sh .
COPY src/ .

# Add a dump-config.py wrapper to /usr/bin so that it can be run
# with 'docker exec CONTAINER_ID dump-config ARGS'.
RUN printf "#!/bin/sh\n" > /usr/bin/dump-config && \
    printf "python3 /root/dump-config.py \$@\n" >> /usr/bin/dump-config && \
    chmod +x /usr/bin/dump-config

CMD ["sh", "docker-entrypoint.sh"]
