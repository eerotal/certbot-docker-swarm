#!/bin/sh

#
# Docker entrypoint for the Docker Swarm compatible Certbot image.
#
# This entrypoint automatically generates initial certificates on first
# boot and renews them automatically before expiry. Certificates are also
# automatically deployed into the Swarm cluster as Docker Secrets.
#

set -e

. /root/config.sh

# Make sure the Docker socket is available.
if [ ! -e "${DOCKER_SOCK}" ]; then
    printf "[ERROR] You must mount the Docker socket at ${DOCKER_SOCK}.\n"
    exit 1
fi

# Check that all necessary env vars are set.
if [ "${CB_AGREE_TOS}" != "y" ]; then
    printf "[ERROR] You must agree to the ACME server's TOS by "
    printf "setting the env var CB_AGREE_TOS=y.\n"
    exit 1
fi
if [ -z "${CB_EMAIL}" ]; then
    printf "[ERROR] You must set your E-mail in the env var CB_EMAIL.\n"
    exit 1
fi
if [ -z "${CB_DOMAINS}" ]; then
    printf "[ERROR] You must set your domains in the env var CB_DOMAINS.\n"
    exit 1
fi
if [ ! -d "${CB_CONFDIR}" ]; then
    printf "[ERROR] You must mount a volume at $CB_CONFDIR.\n"
    exit 1
fi

CB_RUN_ARGS="\
    ${CB_RUN_ARGS} \
    --non-interactive \
    --standalone \
    --agree-tos \
    --preferred-challenges=http \
    --email=$CB_EMAIL \
    --domains=$CB_DOMAINS
"

CB_RENEW_ARGS="\
    ${CB_RENEW_ARGS} \
"

# Enable Docker Swarm deployment if needed.
if [ "${CB_AUTO_DEPLOY}"  = "y" ]; then
    printf "[INFO] Enabling automatic deployment.\n"
    CB_RUN_ARGS="${CB_RUN_ARGS} --installer=docker-swarm"
fi

# Use staging servers if the user has enabled them.
if [ "$CB_STAGING" = "y" ]; then
    printf "[WARNING] Using the ACME server's staging server!\n"
    CB_RUN_ARGS="${CB_RUN_ARGS} --staging"
    CB_RENEW_ARGS="${CB_RENEW_ARGS} --staging"
fi

# Give/don't give the supplied E-mail address to EFF based on user preferences.
if [ "$CB_EFF_EMAIL" = "y" ]; then
    printf "[INFO] You have chosen to give EFF your E-mail address.\n"
    CB_RUN_ARGS="${CB_RUN_ARGS} --eff-email"
else
    CB_RUN_ARGS="${CB_RUN_ARGS} --no-eff-email"
fi

# Run certbot once to make sure certificates exist.
printf "[INFO] Running certbot.\n"
/usr/bin/certbot run ${CB_RUN_ARGS}

# Create a CRON entry for renewing certificates.
printf "[INFO] Installing cron.d entry.\n"
printf "${CRON_EXPR} /usr/bin/certbot renew ${CB_RENEW_ARGS} " \
       ">> /proc/1/fd/1 2>&1\n" | crontab -

printf "[INFO] Starting cron.\n"
crond -f
