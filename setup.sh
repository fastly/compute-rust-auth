#!/bin/bash
printInGreen() {
    echo -e "\033[0;32m ✔️ $1 \033[0m
    "
}

echo -e "

Press ^C at any time to quit.
"
read -p "Origin server host [httpbin.org] " TLS_ORIGIN_HOST
TLS_ORIGIN_HOST=${TLS_ORIGIN_HOST:-"httpbin.org"}
printInGreen $TLS_ORIGIN_HOST

read -p "Authorization server host [dev-0y7s8dkt.us.auth0.com] " AUTH_SERVER_HOST
AUTH_SERVER_HOST=${AUTH_SERVER_HOST:-"dev-0y7s8dkt.us.auth0.com"}
printInGreen $AUTH_SERVER_HOST

read -p "Client ID [m0dfcl4aX3qshMnXrng67qGHZBS9mJ1z] " CLIENT_ID
CLIENT_ID=${CLIENT_ID:-"m0dfcl4aX3qshMnXrng67qGHZBS9mJ1zxv"}
printInGreen $CLIENT_ID

echo "Generating a random, non-guessable secret..."
NONCE_SECRET=$(dd if=/dev/random bs=32 count=1 | base64)
printInGreen $NONCE_SECRET

# Update the service configuration file (src/config.toml)
sed -i.bak "s|client_id = .*|client_id = \"$CLIENT_ID\"|" src/config.toml 
sed -i.bak "s|nonce_secret = .*|nonce_secret = \"$NONCE_SECRET\"|" src/config.toml 
rm -f src/config.toml.bak

echo "Attempting to download OpenID Connect discovery metadata from $AUTH_SERVER_HOST..."
mkdir -p src/well-known
# Download the OpenID Configuration metadata. 
curl -sLX GET https://$AUTH_SERVER_HOST/.well-known/openid-configuration \
    | tr -d "[:space:]" > src/well-known/openid-configuration.json
# Download the JWKS metadata. 
curl -sLX GET $(sed 's|.*"jwks_uri":"\([^"]*\).*|\1|' src/well-known/openid-configuration.json) \
    > src/well-known/jwks.json

printInGreen "All set! Let's create a Compute@Edge service by running \033[1mfastly compute init"

echo -e "✨ \033[0;33mKeep selecting the defaults by pressing the enter key.\033[0m ✨
"

fastly compute init

echo -e "
✨ \033[0;33mBuilding and deploying the service. Why not brew a cup of tea?\033[0m ✨
"

fastly compute build
fastly compute deploy

printInGreen "All set! Let's create the backends for your origin and the authorization server."

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
createTlsBackend $SERVICE_ID $NEXT_VERSION idp $AUTH_SERVER_HOST

# Origin backend
createTlsBackend $SERVICE_ID $NEXT_VERSION backend $TLS_ORIGIN_HOST

printInGreen "All set! Let's activate the service."

# Activate
fastly service-version activate --service-id=$SERVICE_ID --version=$(($NEXT_VERSION+0))
