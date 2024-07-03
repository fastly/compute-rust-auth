# Fastly Compute OAuth application starter kit

Connect to an identity provider such as Okta, Auth0, Azure AD, Google, or Amazon Cognito using OAuth 2.0 and validate authentication status at the Edge, to authorize access to your edge or origin hosted applications.

**For more details about other starter kits for Compute, see the [Fastly developer hub](https://developer.fastly.com/solutions/starters)**

## Authentication at Fastly's edge, using OAuth 2.0, OpenID Connect, and Fastly Compute

This is a self-contained Rust implementation 🦀  for the [OAuth 2.0](https://oauth.net/2/) [Authorization Code flow](https://oauth.net/2/grant-types/authorization-code/) with [Proof Key for Code Exchange (PKCE)](https://oauth.net/2/pkce/), deployed to [Compute](https://www.fastly.com/products/edge-compute/serverless/).

It includes [JSON Web Token (JWT)](https://oauth.net/2/jwt/) verification, and [access token introspection](https://oauth.net/2/token-introspection/).

![A simplified flow diagram of authentication using Compute](https://user-images.githubusercontent.com/12828487/111877689-4b876500-899c-11eb-9d6c-6ecc240fa317.png)

Scroll down to view [the flow in more detail](#the-flow-in-detail).

## Getting started

After you have installed the starter kit, you'll need to do some configuration before you can deploy it, so that Fastly knows which identity provider to use and how to authenticate.

### 1. Set up an identity provider

You might operate your own identity service, but any [OAuth 2.0, OpenID Connect (OIDC) conformant provider](https://en.wikipedia.org/wiki/List_of_OAuth_providers) (IdP) will work.  You will need the following from your IdP:

* A *Client ID* 
* For some IdPs, a *Client Secret* 
* The hostname of the IdP's *authorization server* 
* An *OpenID Connect (OIDC) Discovery document*, typically at `https://{authorization-server-hostname}/.well-known/openid-configuration`
* A *JSON Web key set* 

#### Example: Google

This starter kit is pre-configured to work with Google OAuth clients, so if you are using Google, follow these steps:

1. In the [Google API Console](https://console.cloud.google.com/), search for "oauth" and navigate to the [Credentials](https://console.cloud.google.com/apis/credentials) page. Select **+ Create Credentials** > **OAuth client ID**.
   1. Select the **Web application** type and give your app a name.
   1. Add `http://127.0.0.1:7676` and `http://127.0.0.1:7676/callback` to **Authorized JavaScript origins** and **Authorized redirect URIs**, respectively. This is for local testing only; remember to remove these URLs later!
   1. Tap **Create**.
1. Store your newly created credentials in new (gitignored) files in the root of your Compute project:
   - Paste the *client ID* in `.secret.client_id`
   - Paste the *client secret* in `.secret.client_secret` 
   - Type a long, non-guessable random string of your choice into `.secret.nonce_secret`
      ```sh
      dd if=/dev/random bs=32 count=1 | base64 > .secret.nonce_secret
      ```
1. Fetch Google's OIDC Discovery document from [accounts.google.com/.well-known/openid-configuration](https://accounts.google.com/.well-known/openid-configuration). Paste the JSON-stringified contents of the file into the `openid_configuration` property in `fastly.toml`, under `[local_server.config_stores.oauth_config.contents]`.
   ```sh
   curl -s https://accounts.google.com/.well-known/openid-configuration | jq -c @json
   ```
1. Note the `jwks_uri` property inside the OIDC Discovery document. Fetch the document at that URL and paste its JSON-stringified contents into the `jwks` property in `fastly.toml`, under `[local_server.config_stores.oauth_config.contents]`.
   ```sh
   curl -s https://www.googleapis.com/oauth2/v3/certs | jq -c @json
   ```

### 2. Test your configuration locally

Spin up the local development server for your Compute service:

```term
fastly compute serve
```

Browse to http://127.0.0.1:7676. If everything is configured correctly, you should be able to complete an end-to-end OAuth 2.0 flow.

### 3. Deploy the Fastly service and get a domain

Now you can build and deploy your new service:

```term
fastly compute publish
```

This will run through the [`setup` configuration](https://www.fastly.com/documentation/reference/compute/fastly-toml/#setup-information) defined in `fastly.toml` before building and publishing your Compute service.

You'll be prompted to enter the hostname of your own origin to configure the backend called `origin`, and also the authorization server of the identity provider (IdP) which will be used to configure a backend called `idp`. 

A [secret store](https://docs.fastly.com/en/guides/working-with-secret-stores) called `oauth_secrets` will automatically be created, and you'll be prompted for your `client_id`, `client_secret` and `nonce_secret`.

A [config store](https://docs.fastly.com/en/guides/working-with-config-stores) called `oauth_config` will automatically be created, and you'll be prompted to input values for `openid_configuration` and `jwks`. You can find these in `fastly.toml` if you followed the instructions in [Step 1](#example-google).

When the deploy is finished you'll be given a Fastly-assigned domain such as `random-funky-words.edgecompute.app`.

### 4. Link the identity provider to your Fastly domain

Add `https://{your-fastly-domain}/callback` to the list of allowed callback URLs in your IdP's app configuration (for Google, this is **Authorized redirect URIs** within your application's OAuth 2.0 Client **Credentials**).

This allows the authorization server to send the user back to the Compute service.

### 5. Try it out!

Now you can visit your Fastly-assigned domain.  You should be prompted to follow a login flow with your identity provider, and then after successfully authenticating, will see content delivered from your own origin.

---

## The flow in detail

Here is how the authentication process works:

![Edge authentication flow diagram](https://user-images.githubusercontent.com/12828487/115379253-4438be80-a1c9-11eb-81af-9470e324434a.png)

1. The user makes a request for a protected resource, but they have no session cookie.
1. At the edge, this service generates:
   * A unique and non-guessable `state` parameter, which encodes what the user was trying to do (e.g., load `/articles/kittens`).
   * A cryptographically random string called a `code_verifier`.
   * A `code_challenge`, derived from the `code_verifier`.
   * A time-limited token, authenticated using the `nonce_secret`, that encodes the `state` and a `nonce` (a unique value used to mitigate replay attacks).
1. The `state` and `code_verifier` are stored in session cookies.
1. The service builds an authorization URL and redirects the user to the **authorization server** operated by the IdP.
1. The user completes login formalities with the IdP directly.
1. The IdP will include an `authorization_code` and a `state` (which should match the time-limited token we created earlier) in a post-login callback to the edge.
1. The edge service authenticates the `state` token returned by the IdP, and verifies that the state cookie matches its subject claim.
1. Then, it connects directly to the IdP and exchanges the `authorization_code` (which is good for only one use) and `code_verifier` for **security tokens**:
   * An `access_token` – a key that represents the authorization to perform specific operations on behalf of the user)
   * An `id_token`, which contains the user's profile information.
1. The end-user is redirected to the original request URL (`/articles/kittens`), along with their security tokens stored in cookies.
1. When the user makes the redirected request (or subsequent requests accompanied by security tokens), the edge verifies the integrity, validity and claims for both tokens. If the tokens are still good, it proxies the request to your origin.

## Configuration

### Secrets

The following secrets must be stored in the `oauth_secrets` [secret store](https://docs.fastly.com/en/guides/working-with-secret-stores) associated with the Compute service:

| Secret | Description |
|---|---|
| `client_id` | [OAuth 2.0 client identifier](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1) valid at the IdP's authorization server. |
| `nonce_secret` | A secret to verify the [OpenID nonce](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest) used to mitigate replay attacks. It must be sufficiently random to not be guessable. |
| `client_secret` (optional) | Optional client secret for certain IdPs' `token` endpoint. Google, for example, [requires a client secret](https://developers.google.com/identity/protocols/oauth2/native-app#exchange-authorization-code) obtained from its API console. WARNING: Including this parameter produces [NON-NORMATIVE OAuth 2.0 token requests](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.1). |

### Optional configuration

The following keys may be stored in the `oauth_config` [config store](https://docs.fastly.com/en/guides/working-with-config-stores) associated with the Compute service:

| Key | Description | Default |
|---|---|---|
| `callback_path` | Path for the [redirection URI](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1) to which OAuth 2.0 responses will be sent. | `/callback` |
| `scope` | OAuth 2.0 [scope list](https://oauth.net/2/scope) (one or more space-separated scopes). | `openid` |
| `introspect_access_token` | Whether to verify the access token using the [OpenID userinfo endpoint](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.3). Used to introspect opaque and other types of tokens revocable by the authorization server. If revocation is not a concern – or when IdP rate limits are – set to `true` to validate JWT access tokens at the edge. | `false` |
| `jwt_access_token` | Whether the access token is a [JWT](https://tools.ietf.org/html/rfc7519). JWT access tokens may be validated at the edge, using an approach similar to ID tokens. Omitted if `introspect_access_token` is `true`. | `false` |
| `code_challenge_method` | [PKCE code challenge](https://datatracker.ietf.org/doc/html/rfc7636#section-4.3) method. | `S256` |

## Issues

If you encounter any non-security-related bug or unexpected behavior, please [file an issue][bug]
using the bug report template.

[bug]: https://github.com/fastly/compute-rust-auth/issues/new?labels=bug

### Security issues

Please see our [SECURITY.md](./SECURITY.md) for guidance on reporting security-related issues.
