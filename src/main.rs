mod config;
mod cookies;
mod idp;
mod jwt;
mod pkce;
mod responses;

use config::Config;
use fastly::http::header::AUTHORIZATION;
use fastly::{Error, Request, Response};
use idp::{AuthCodePayload, AuthorizeResponse, CallbackQueryParameters, ExchangePayload};
use jwt::{validate_token_rs256, NonceToken};
use jwt_simple::claims::NoCustomClaims;
use pkce::{rand_chars, Pkce};

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Log service version
    println!(
        "FASTLY_SERVICE_VERSION: {}",
        std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );

    // Load the service configuration, and the OpenID discovery and token signature metadata.
    let settings = Config::load();

    // Parse the Cookie header.
    let cookie_header = req.remove_header_str("cookie").unwrap_or_default();
    let cookie = cookies::parse(&cookie_header);

    // Build the OAuth 2.0 redirect URL.
    let redirect_uri = format!(
        "https://{}{}",
        req.get_url().host_str().unwrap(),
        settings.config.callback_path
    );

    // If the path matches the redirect URL path, continue the OAuth 2.0 authorization code flow.
    if req.get_url_str().starts_with(&redirect_uri) {
        // VERIFY THE AUTHORIZATION CODE AND EXCHANGE IT FOR TOKENS.

        // Retrieve the code and state from the query string.
        let qs: CallbackQueryParameters = req.get_query().unwrap();
        // Verify that the state matches what we've stored, and exchange the authorization code for tokens.
        return match (cookie.get("state"), cookie.get("code_verifier")) {
            (Some(state), Some(code_verifier)) => {
                // Authenticate the state token returned by the IdP,
                // and verify that the state we stored matches its subject claim.
                match NonceToken::new(settings.config.nonce_secret).get_claimed_state(&qs.state) {
                    Some(claimed_state) => {
                        if state != &claimed_state {
                            return Ok(responses::unauthorized("State mismatch."));
                        }
                    }
                    _ => {
                        return Ok(responses::unauthorized("Could not verify state."));
                    }
                };
                // Exchange the authorization code for tokens.
                let mut exchange_res = Request::post(settings.openid_configuration.token_endpoint)
                    .with_body_form(&ExchangePayload {
                        client_id: settings.config.client_id,
                        client_secret: settings.config.client_secret,
                        code: &qs.code,
                        code_verifier,
                        grant_type: "authorization_code",
                        redirect_uri: &redirect_uri,
                    })
                    .unwrap()
                    .send("idp")?;
                // If the exchange is successful, proceed with the original request.
                if exchange_res.get_status().is_success() {
                    // Strip the random state from the state cookie value to get the original request.
                    let original_req =
                        &state[..(state.len() - settings.config.state_parameter_length)];
                    // Deserialize the response from the authorize step.
                    let auth = exchange_res.take_body_json::<AuthorizeResponse>().unwrap();
                    // Replay the original request, setting the tokens as cookies.
                    Ok(responses::temporary_redirect(
                        original_req,
                        cookies::persistent("access_token", &auth.access_token, auth.expires_in),
                        cookies::persistent("id_token", &auth.id_token, auth.expires_in),
                        cookies::expired("code_verifier"),
                        cookies::expired("state"),
                    ))
                // Otherwise, surface any errors from the Identity Provider.
                } else {
                    Ok(responses::unauthorized(exchange_res.take_body()))
                }
            }
            _ => Ok(responses::unauthorized("State cookies not found.")),
        };
    }

    // Verify any tokens stored as a result of a complete OAuth 2.0 authorization code flow.
    if let (Some(access_token), Some(id_token)) =
        (cookie.get("access_token"), cookie.get("id_token"))
    {
        if settings.config.introspect_access_token {
            // Validate the access token using the OpenID userinfo endpoint;
            // bearer authentication supports opaque, JWT and other token types (PASETO, Hawk),
            // depending on your Identity Provider configuration.
            let mut userinfo_res = Request::get(settings.openid_configuration.userinfo_endpoint)
                .with_header(AUTHORIZATION, format!("Bearer {}", access_token))
                .send("idp")?;
            // Surface any errors and respond early.
            if userinfo_res.get_status().is_client_error() {
                return Ok(responses::unauthorized(userinfo_res.take_body()));
            }
        // Validate the JWT access token.
        } else if settings.config.jwt_access_token
            && validate_token_rs256::<NoCustomClaims>(access_token, &settings).is_err()
        {
            return Ok(responses::unauthorized("JWT access token invalid."));
        }

        // Validate the ID token.
        if validate_token_rs256::<NoCustomClaims>(id_token, &settings).is_err() {
            return Ok(responses::unauthorized("ID token invalid."));
        }

        // Authorization and authentication successful!

        // Modify the request before routing to the origin backend, e.g.:
        // Add an API key;
        req.set_header("x-api-key", "h3ll0fr0mc0mpu73@3dg3");
        // Add a custom header containing the access token;
        req.set_header("fastly-access-token", *access_token);
        // Add a custom header containing the ID token;
        req.set_header("fastly-id-token", *id_token);

        // Send the request to the origin backend.
        return Ok(req.send("backend")?);
    }

    // Otherwise, start the OAuth 2.0 authorization code flow.

    // Generate the Proof Key for Code Exchange (PKCE) code verifier and code challenge.
    let pkce = Pkce::new(settings.config.code_challenge_method);
    // Generate the OAuth 2.0 state parameter, used to prevent CSRF attacks,
    // and store the original request path and query string.
    let state = {
        let path = req.get_path();
        let (sep, query) = match req.get_query_str() {
            Some(q) => ("?", q),
            None => ("", ""),
        };
        let rand_chars = rand_chars(settings.config.state_parameter_length);
        format!("{}{}{}{}", path, sep, query, rand_chars)
    };
    // Generate the OpenID Connect nonce, used to mitigate replay attacks.
    // This is a random value with a twist: in is a time limited token (JWT)
    // that encodes the nonce and the state within its claims.
    let (state_and_nonce, nonce) =
        NonceToken::new(settings.config.nonce_secret).generate_from_state(&state);

    // Build the authorization request.
    let authorize_req = Request::get(settings.openid_configuration.authorization_endpoint)
        .with_query(&AuthCodePayload {
            client_id: settings.config.client_id,
            code_challenge: &pkce.code_challenge,
            code_challenge_method: settings.config.code_challenge_method,
            redirect_uri: &redirect_uri,
            response_type: "code",
            scope: &settings.config.scope,
            state: &state_and_nonce,
            nonce: &nonce,
        })
        .unwrap();
    // Redirect to the Identity Provider's login and authorization prompt.
    Ok(responses::temporary_redirect(
        authorize_req.get_url_str(),
        cookies::expired("access_token"),
        cookies::expired("id_token"),
        cookies::session("code_verifier", &pkce.code_verifier),
        cookies::session("state", &state),
    ))
}
