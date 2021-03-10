# Authentication at Fastly's edge, using OAuth 2.0, OpenID Connect, and Compute@Edge

This is a self-contained Rust implementation 🦀 for [OAuth 2.0](https://oauth.net/2/) [Authorization Code flow](https://oauth.net/2/grant-types/authorization-code/) with [Proof Key for Code Exchange (PKCE)](https://oauth.net/2/pkce/), for [Compute@Edge](https://www.fastly.com/products/edge-compute/serverless/).

It includes [JSON Web Token (JWT)](https://oauth.net/2/jwt/) verification, and [access token introspection](https://oauth.net/2/token-introspection/).

![Authentication using Compute@Edge](https://user-images.githubusercontent.com/12828487/110628616-270cdb00-819b-11eb-8510-0600635c5808.png)

Scroll down to view [the flow in more detail](#the-flow-in-detail).

For Compute@Edge starter kits, see the [Fastly Developer Hub](https://developer.fastly.com/solutions/starters/). 

## Setting up edge authentication

### 1. Getting an identity provider (IdP)

> 💡 You might operate your own identity service, but any [OAuth 2.0, OpenID Connect (OIDC) conformant provider](https://en.wikipedia.org/wiki/List_of_OAuth_providers) will do.

1. Register your application with the IdP. Make a note of the `client_id` and the address of the **authorization server**.
2. Save a local copy of the OpenID Connect discovery document associated with the server. You’ll find this at `/.well-known/openid-configuration` on the authorization server’s domain. For example, [here's the one provided by Google](https://accounts.google.com/.well-known/openid-configuration).
3. Save a local copy of the JSON Web Key Set (JWKS) metadata. You’ll find this under the `jwks_uri` property in the discovery document you just downloaded.

### 2. Creating the Compute@Edge service

> 💡 You will need to have a Fastly account that is [enabled for Compute@Edge services](https://www.fastly.com/products/edge-compute/serverless/). Follow the [Compute@Edge welcome guide](https://developer.fastly.com/learning/compute) to install the `fastly` CLI and the Rust toolchain onto your local machine. 

1. Type `fastly compute init`
   * When prompted for a starter kit, instead of choosing one of the provided options, paste this URL instead:
   https://github.com/fastly/compute-rust-auth
   * When prompted to create a backend, accept the default *originless* option.
1. Open [`src/config.toml`](./src/config.toml) and paste in the `client_id`.
1. Run `fastly compute build` and then `fastly compute deploy`. Note the hostname of the deployed Compute@Edge service (e.g., `{some-funky-words}.edgecompute.app`).
1. Open [`setup.sh`](./setup.sh) and paste in the authorization server host, and the host of your origin server.
1. Run `./setup.sh` – this will:
   * Add two backends to your Compute@Edge service, `idp` and `backend`.
   * Attempt to download the OpenID Connect and JWKS metadata for the authorization server, and redeploy your Fastly service on success.
   * If this fails, [create the two backends manually](https://developer.fastly.com/reference/cli/backend/create/) and copy the OpenID and JWKS metadata files to `src/well-known/openid-configuration.json` and `src/well-known/jwks.json`, respectively, and then rebuild and deploy the service.

### 3. Link the identity provider

Add `https://{some-funky-words}.edgecompute.app/callback` to the list of allowed callback URLs in your IdP’s app configuration. This allows the authorization server to send the user back to the Compute@Edge service.


## The flow in detail

1. The user makes a request for a protected resource, but they have no session cookie.
1. At the edge, this service generates:
   * A unique and non-guessable `state` parameter, which encodes what the user was trying to do (e.g., load `/articles/kittens`).
   * A cryptographically random passcode called a `code_verifier`.
   * A `code_challenge`, which encodes the `code_verifier`. 
1. The `state` and `code_verifier` are stored in session cookies. 
1. The service builds an authorization URL and redirects the user to the **authorization server** operated by the IdP.
1. The user completes login formalities with the IdP directly. 
1. The IdP will include an `authorization_code` and a `state` parameter in a post-login callback to the edge.
1. The edge service checks that the `state` parameter matches the one stored earlier.
1. Then, it connects directly to the IdP and exchanges the `authorization_code` (which is good for only one use) and `code_verifier` for **security tokens**:
   * An `access_token` – a key that represents the authorization to perform specific operations on behalf of the user)
   * An `id_token` (which contains the user's profile information).
1. The end-user is redirected to the original request URL (`/articles/kittens`), along with their security tokens stored in cookies.
1. When the user makes the redirected request (or subsequent requests accompanied by security tokens), the edge verifies the integrity, validity and claims for both tokens. If the tokens are still good, it proxies the request to your origin.

