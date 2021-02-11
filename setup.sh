#!/bin/bash
IDP_HOST=dev-0y7s8dkt.us.auth0.com
TLS_ORIGIN_HOST=httpbin.org

SERVICE_ID=$(awk -F'[ ="]+' '$1 == "service_id" { print $2 }' fastly.toml)
VERSION=$(awk -F'[ =]+' '$1 == "version" { print $2 }' fastly.toml)
NEXT_VERSION=$(fastly service-version clone --service-id=$SERVICE_ID --version=$VERSION | awk '{ print $NF }')

createTlsBackend() {
    fastly backend delete --service-id=$1 --version=$2 --name=$3
    fastly backend create --service-id=$1 --version=$2 --name=$3 \
        --port=443 --address=$4 --override-host=$4 --ssl-sni-hostname=$4 --ssl-cert-hostname=$4 \
        --use-ssl --ssl-check-cert
}

# Identity Provider backend
createTlsBackend $SERVICE_ID $NEXT_VERSION idp $IDP_HOST

# Origin backend
createTlsBackend $SERVICE_ID $NEXT_VERSION backend $TLS_ORIGIN_HOST

# Activate
fastly service-version activate --service-id=$SERVICE_ID --version=$(($NEXT_VERSION+0))
