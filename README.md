# Compute@Edge OAuth application starter kit

Connect to an identity provider such as Auth0 using OAuth 2.0 and validate authentication status at the Edge, to authorize access to your edge or origin hosted applications.

**For more details about other starter kits for Compute@Edge, see the [Fastly developer hub](https://developer.fastly.com/solutions/starters)**

## Authentication at Fastly's edge, using OAuth 2.0, OpenID Connect, and Compute@Edge

This is a self-contained Rust implementation 🦀  for the [OAuth 2.0](https://oauth.net/2/) [Authorization Code flow](https://oauth.net/2/grant-types/authorization-code/) with [Proof Key for Code Exchange (PKCE)](https://oauth.net/2/pkce/), deployed to [Compute@Edge](https://www.fastly.com/products/edge-compute/serverless/).

It includes [JSON Web Token (JWT)](https://oauth.net/2/jwt/) verification, and [access token introspection](https://oauth.net/2/token-introspection/).

![A simplified flow diagram of authentication using Compute@Edge](https://user-images.githubusercontent.com/12828487/111877689-4b876500-899c-11eb-9d6c-6ecc240fa317.png)

Scroll down to view [the flow in more detail](#the-flow-in-detail).
## Getting started

After you have installed the starter kit, you'll need to do some configuration before you can deploy it, so that Fastly knows which identity provider to use and how to authenticate.

### Set up an identity provider

You might operate your own identity service, but any [OAuth 2.0, OpenID Connect (OIDC) conformant provider](https://en.wikipedia.org/wiki/List_of_OAuth_providers) (IdP) will work.  You will need the following from your IdP:

* A *Client ID* -> Add to `src/config.toml`
* An *OpenID Connect Discovery document* -> Save as `src/well-known/openid-configuration.json`
* A *JSON Web key set* -> Save as `src/well-known/jwks.json`
* The hostname of the IdP's *authorization server* -> Create as a backend called `idp` on your Fastly service

As an example, if you are using Auth0, follow these steps after installing the starter kit:

1. In the [Auth0 dashboard](https://manage.auth0.com/), choose **Create Application**. Give your app a name and choose "Regular web application".
   - The *client ID* (eg. `4PWZBMqMWxnKXt1heitack0Jy2xRQP0p`) is shown next to your application name.
1. Open `src/config.toml` in your Fastly project and paste in the `client_id` from your IdP.  Set the `nonce_secret` field to a long, non-guessable random string of your choice.  Save the file.
1. Back in Auth0's dashboard, click **Settings**, and note down the *authorization server* hostname (eg. `dev-wna8lqtb.us.auth0.com`) is shown in the **Domain** field.
1. In a new tab, navigate to `https://{authorization-server-hostname}/.well-known/openid-configuration`.  Save it to `src/well-known/openid-configuration.json` in your Fastly project.
1. Open the file you just created and locate the `jwks_uri` property.  Fetch the document at that URL and save it to `src/well-known/jwks.json` in your Fastly project.

### Deploy the Fastly service and get a domain

Now you can build and deploy your new service:

```term
$ fastly compute publish
```

You'll be prompted to enter the hostname of your own origin to configure the backend called `backend`, and also the authorization server of the identity provider which will be used to configure a backend called `idp`.  When the deploy is finished you'll be given a Fastly-assigned domain such as `random-funky-words.edgecompute.app`.
### Link the identity provider to your Fastly domain

Add `https://{your-fastly-domain}/callback` to the list of allowed callback URLs in your identity provide's app configuration (In Auth0, within your application's **Settings** tab, the field is labelled **Allowed Callback URLs**).

This allows the authorization server to send the user back to the Compute@Edge service.

### Try it out!

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

## Issues

If you encounter any non-security-related bug or unexpected behavior, please [file an issue][bug]
using the bug report template.

[bug]: https://github.com/fastly/compute-rust-auth/issues/new?labels=bug

### Security issues

Please see our [SECURITY.md](./SECURITY.md) for guidance on reporting security-related issues.
