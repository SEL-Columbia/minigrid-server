#!/usr/bin/env sh
# Minigrid Server installer for version 0.1.6-dev14
set -e

# Do you have docker installed?
if ! command -v docker > /dev/null; then
  printf "You need to install docker\n"
  exit 1
fi

# Do you have sed installed?
if ! command -v sed > /dev/null; then
  printf "You need to install sed\n"
  exit 1
fi

# Do you have openssl installed?
if ! command -v openssl > /dev/null; then
  printf "You need to install openssl\n"
  exit 1
fi

# Do you have curl installed?
if command -v curl > /dev/null; then
  CURL=curl
else
  CURL="docker run tutum/curl curl"
fi

# Do you have docker-compose installed?
if command -v docker-compose > /dev/null; then
  DOCKER_COMPOSE=docker-compose
else
  DOCKER_COMPOSE=./docker-compose
  if ! [ -f ./docker-compose ]; then
    printf "========================================\n"
    printf " Installing docker-compose in this      \n"
    printf " directory                              \n"
    printf "========================================\n"
    $CURL -L https://github.com/docker/compose/releases/download/1.9.0/run.sh > docker-compose \
      && chmod +x docker-compose
    ./docker-compose -v
  fi
fi

# This installer needs root access for various reasons...
# Copy the logic from the letsencrypt-auto script
# https://github.com/letsencrypt/letsencrypt/blob/8c6e242b13ac818c0a94e3dceee81ab4b3816a12/letsencrypt-auto#L34-L68
if test "`id -u`" -ne "0" ; then
  if command -v sudo 1>/dev/null 2>&1; then
    SUDO=sudo
  else
    echo \"sudo\" is not available, will use \"su\" for installation steps...
    su_sudo() {
      args=""
      while [ $# -ne 0 ]; do
        args="$args'$(printf "%s" "$1" | sed -e "s/'/'\"'\"'/g")' "
        shift
      done
      su root -c "$args"
    }
    SUDO=su_sudo
  fi
else
  SUDO=
fi

# Ask for domain(s)
printf "========================================\n"
printf " Please enter your domain name(s) (space\n"
printf " separated)                             \n"
printf "                                        \n"
printf " Hint: for www include both             \n"
printf " >>> www.your.domain your.domain        \n"
printf "                                        \n"
printf " For a subdomain just give              \n"
printf " >>> subdomain.your.domain              \n"
printf "========================================\n"
printf "Domain(s):\n>>> "
read DOMAINS
LETSENCRYPT_DIR=$(echo $DOMAINS | cut -d' ' -f1)
DOMAIN_ARGS=$(echo $DOMAINS | sed -r s/\([^\ ]+\)/-d\ \\1/g)

# Run letsencrypt
printf "========================================\n"
printf " Installing SSL certificate. Make sure  \n"
printf " you have set up the DNS records for    \n"
printf " your domain to point to this machine.  \n"
printf "========================================\n"
# for some reason these directories need to exist beforehand on Fedora...
$SUDO mkdir -p /etc/letsencrypt
$SUDO mkdir -p /var/lib/letsencrypt
$SUDO docker run -it --rm -p 443:443 -p 80:80 \
  --name certbot \
  -v "/etc/letsencrypt:/etc/letsencrypt:Z" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt:Z" \
  -v "/var/log:/var/log:Z" \
  quay.io/letsencrypt/letsencrypt:latest certonly --standalone $DOMAIN_ARGS

# Run openssl dhparam
printf "========================================\n"
printf " Generating Diffie-Hellman parameters   \n"
printf " using OpenSSL (2048 bit prime)         \n"
printf "========================================\n"
$SUDO openssl dhparam -out /etc/letsencrypt/live/$LETSENCRYPT_DIR/dhparam.pem 2048

# Download the configuration files
printf "========================================\n"
printf " Generating configuration               \n"
printf "========================================\n"
$CURL -L https://raw.githubusercontent.com/SEL-Columbia/minigrid-server/0.1.6-dev14/prod/docker-compose.yml > docker-compose.yml
$CURL -L https://raw.githubusercontent.com/SEL-Columbia/minigrid-server/0.1.6-dev14/prod/nginx.conf > nginx.conf

sed -i s/www.example.com/$LETSENCRYPT_DIR/g docker-compose.yml
sed -i s/www.example.com/$LETSENCRYPT_DIR/g nginx.conf

printf "\n"
printf "Please enter an e-mail address for the  \n"
printf "administrator. This will be the only    \n"
printf "account that can log in at first.       \n"
printf "Administrator e-mail address:\n>>> "
read ADMIN_EMAIL

# Bring up the server
printf "========================================\n"
printf " Starting minigrid server.              \n"
printf "                                        \n"
printf " You can view the status of the         \n"
printf " containers by running:                 \n"
printf " $DOCKER_COMPOSE ps\n"
printf "========================================\n"
if [ -f /etc/redhat-release ] ; then
  chcon -Rt svirt_sandbox_file_t .
fi
$DOCKER_COMPOSE up -d
MINIGRID_CONTAINER_NAME=$($DOCKER_COMPOSE ps | grep _minigrid_ | cut -d' ' -f1)
sleep 1
docker exec $MINIGRID_CONTAINER_NAME ""prod/create_initial_user.py --db-host=db $ADMIN_EMAIL""
docker exec $MINIGRID_CONTAINER_NAME ""prod/create_payment_ids.py --db-host=db""
NGINX_CONTAINER_NAME=$($DOCKER_COMPOSE ps | grep _nginx_ | cut -d' ' -f1)

# Let's Encrypt auto-renew (for now this is a cron job).
printf "========================================\n"
printf " Adding twice-daily cron job to renew   \n"
printf " SSL certificate.                       \n"
printf "========================================\n"
# The --post-hook should just be docker restart $NGINX_CONTAINER_NAME... but
# the container can't run the docker command properly.
# So /tmp/renewed serves as a sentinel
CRON_CMD="mkdir -p /tmp/letsencrypt && "\
"docker run -it --rm --name certbot"\
" -v /etc/letsencrypt:/etc/letsencrypt:Z"\
" -v /var/lib/letsencrypt:/var/lib/letsencrypt:Z"\
" -v /tmp:/tmp:Z"\
" -v /var/log/letsencrypt:/var/log/letsencrypt:Z"\
" quay.io/letsencrypt/letsencrypt renew --quiet --webroot --webroot-path /tmp/letsencrypt --post-hook 'touch /tmp/renewed' ; "\
"if [ -f /tmp/renewed ] ; then docker restart $NGINX_CONTAINER_NAME ; fi ; "\
"rm -f /tmp/renewed"
# https://certbot.eff.org/#ubuntuxenial-nginx recommends running this twice a day on random minute within the hour
CRON_JOB="00 01,13 * * * sleep \$(expr \$RANDOM \% 59 \* 60); $CRON_CMD"
crontab -l | fgrep -i -v "$CRON_CMD" | { cat; echo "$CRON_JOB"; } | crontab -
crontab -l
