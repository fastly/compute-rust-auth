# Compute@Edge, OAuth and OIDC!

## Prerequisites

1. Register a new application with your favourite OAuth 2.0, OpenID Connect conformant Identity Provider. Make a note of your tenant client_id and the address of your authorization server.
1. Save a [local copy](./src/well-known/openid-configuration.json) of the OpenID Connect discovery metadata associated with the server. You’ll find this at https://{shiny-auth-server.com}/well-known/openid-configuration
1. Save a [local copy](./src/well-known/jwks.json) of the JSON Web Key Set (JWKS) metadata. You’ll find this under the jwks_uri property in the document you just downloaded.
1. Paste the client_id you’ve jotted down earlier into config.toml and deploy a Compute@Edge service. Make a note of where it’s deployed.
Add https://{my-shiny-service.edgecompute.app}/callback to the list of allowed callback URLs in your Identity Provider’s app configuration.

## What this does

Here’s everything we need to accomplish at the edge:

1. Create a secret code verifier and code challenge, and store some state objects set by the client in a unique and non-guessable way.
1. Build an authorization URL and redirect the user to the authorization server.
1. After the authenticated user is redirected back to the edge, compare the returned state with the one stored earlier.
1. Exchange the authorization code (which is good for one use) and code verifier for an access token, and an ID token.
1. Verify the integrity, validity and claims of both tokens.
1. Apply any modifications to the original request before routing it to the origin backend.
1. Ensure that the user is both securely authenticated (logged in) and authorized (has the correct permissions) before fulfilling any subsequent requests.
