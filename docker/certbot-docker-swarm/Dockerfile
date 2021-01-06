FROM alpine:3

ENV CB_EMAIL=""
ENV CB_DOMAINS=""
ENV CB_AGREE_TOS="n"
ENV CB_EFF_EMAIL="n"
ENV CB_STAGING="n"
ENV CB_AUTO_DEPLOY="n"
ENV CB_CERTONLY_ARGS=""
ENV CB_RENEW_ARGS=""

USER root
WORKDIR /root

RUN apk add --no-cache \
        certbot \
        docker-py && \
    apk add --no-cache --virtual py3-build-deps \
        git \
        py3-setuptools && \
    git clone https://github.com/eerotal/certbot-docker-swarm.git && \
    cd certbot-docker-swarm && \
    python3 setup.py install && \
    apk del --purge py3-build-deps

COPY docker-entrypoint.sh .
COPY src/ .

CMD ["sh", "docker-entrypoint.sh"]
