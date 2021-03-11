#!/bin/bash
AUTH_SERVER_HOST=dev-0y7s8dkt.us.auth0.com
TLS_ORIGIN_HOST=httpbin.org

fastly compute init

SERVICE_ID=$(awk -F'[ ="]+' '$1 == "service_id" { print $2 }' fastly.toml)
VERSION=$(awk -F'[ =]+' '$1 == "version" { print $2 }' fastly.toml)
NEXT_VERSION=$(fastly service-version clone --service-id=$SERVICE_ID --version=$VERSION | awk '{ print $NF }')

mkdir -p src/well-known

# Download the OpenID Connect well-known metadata. 
getWellKnown() {
    # Download the OpenID Configuration metadata. 
    curl -L -X GET https://$AUTH_SERVER_HOST/.well-known/openid-configuration | tr -d "[:space:]" > src/well-known/openid-configuration.json
    # Parse the JSON Web Key URI.
    JWKS_URI=$(sed 's|.*"jwks_uri":"\([^"]*\).*|\1|' src/well-known/openid-configuration.json)
    # Download the JWKS metadata. 
    [ -z $JWKS_URI ] && curl -L -X GET $JWKS_URI > src/well-known/jwks.json
}

createTlsBackend() {
    fastly backend delete --service-id=$1 --version=$2 --name=$3
    fastly backend create --service-id=$1 --version=$2 --name=$3 \
        --port=443 --address=$4 --override-host=$4 --ssl-sni-hostname=$4 --ssl-cert-hostname=$4 \
        --use-ssl --ssl-check-cert
}

getWellKnown

# Identity Provider backend
createTlsBackend $SERVICE_ID $NEXT_VERSION idp $AUTH_SERVER_HOST

# Origin backend
createTlsBackend $SERVICE_ID $NEXT_VERSION backend $TLS_ORIGIN_HOST

# Activate
fastly service-version activate --service-id=$SERVICE_ID --version=$(($NEXT_VERSION+0))

