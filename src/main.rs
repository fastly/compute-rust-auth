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
use jwt::validate_token_rs256;
use pkce::{rand_chars, Pkce};

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Load the service configuration, and the OpenID discovery and token signature metadata.
    let settings = Config::load();

    // Verify any tokens stored as a result of a complete OAuth 2.0 authorization code flow.
    let cookie_header = req.remove_header_str("cookie").unwrap_or_default();
    let cookie = cookies::parse(&cookie_header);

    if let (Some(access_token), Some(id_token)) =
        (cookie.get("access_token"), cookie.get("id_token"))
    {
        if settings.config.verify_access_token {
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
            && validate_token_rs256(access_token, &settings).is_err()
        {
            return Ok(responses::unauthorized(
                "JWT access token invalid. Try again...",
            ));
        }

        // Validate the ID token.
        if validate_token_rs256(id_token, &settings).is_err() {
            return Ok(responses::unauthorized("ID token invalid. Try again..."));
        }

        // Authorization and authentication successful!

        // Modify the request before routing to the origin backend, e.g.:
        // Add an API key;
        req.set_header("x-api-key", "h3ll0fr0mf457lyc0mpu73@3d63");
        // Add a custom header containing the access token;
        req.set_header("access-token", *access_token);
        // Add a custom header containing the ID token;
        req.set_header("id-token", *id_token);
        // Or authenticate using AWS Signature V4: https://github.com/fastly/compute-starter-kit-rust-static-content

        // Send the request to the origin backend.
        return Ok(req.send("backend")?);
    }

    // Start or continue the OAuth 2.0 authorization code flow.

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
        match (cookie.get("state"), cookie.get("code_verifier")) {
            (Some(state), Some(code_verifier))
                if base64::encode_config(state, base64::URL_SAFE_NO_PAD) == qs.state =>
            {
                // Exchange the authorization code for tokens.
                let mut exchange_res = Request::post(settings.openid_configuration.token_endpoint)
                    .with_body_form(&ExchangePayload {
                        client_id: &settings.config.client_id,
                        client_secret: settings.config.client_secret,
                        code: &qs.code,
                        code_verifier: code_verifier,
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
                        cookies::permanent("access_token", &auth.access_token, auth.expires_in),
                        cookies::permanent("id_token", &auth.id_token, auth.expires_in),
                        cookies::expired("code_verifier"),
                        cookies::expired("state"),
                    ))
                // Otherwise, surface any errors from the Identity Provider.
                } else {
                    Ok(responses::unauthorized(exchange_res.take_body()))
                }
            }
            _ => Ok(responses::unauthorized(
                "State parameter mismatch. Try again...",
            )),
        }
    // Otherwise, start the OAuth 2.0 authorization code flow.
    } else {
        // REQUEST AN AUTHORIZATION CODE.

        // Generate the Proof Key for Code Exchange (PKCE) code verifier and code challenge.
        let pkce = Pkce::new(&settings.config.code_challenge_method);
        // Generate the Oauth 2.0 state parameter,
        // adding a nonce to the original request URL to prevent attacks and redirect users.
        let state = format!(
            "{}{}{}",
            req.get_path(),
            req.get_query_str().unwrap_or(""),
            rand_chars(settings.config.state_parameter_length)
        );
        // Build the authorization request.
        let authorize_req = Request::get(settings.openid_configuration.authorization_endpoint)
            .with_query(&AuthCodePayload {
                client_id: &settings.config.client_id,
                code_challenge: &pkce.code_challenge,
                code_challenge_method: &settings.config.code_challenge_method,
                redirect_uri: &redirect_uri,
                response_type: "code",
                scope: "openid",
                state: &base64::encode_config(&state, base64::URL_SAFE_NO_PAD),
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
}
