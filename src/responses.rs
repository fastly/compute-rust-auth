use crate::cookies;
use fastly::http::{header::SET_COOKIE, StatusCode};
use fastly::{Body, Response};

pub fn unauthorized(body: impl Into<Body>) -> Response {
    let mut res = Response::from_body(body)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_header(SET_COOKIE, cookies::expired("access_token"));
    res.append_header(SET_COOKIE, cookies::expired("id_token"));
    res.append_header(SET_COOKIE, cookies::expired("code_verifier"));
    res.append_header(SET_COOKIE, cookies::expired("state"));
    res
}

pub fn temporary_redirect(
    location: &str,
    access_token_cookie: String,
    id_token_cookie: String,
    code_verifier_cookie: String,
    state_cookie: String,
) -> Response {
    let mut res = Response::from_status(StatusCode::TEMPORARY_REDIRECT)
        .with_header("location", location)
        .with_header(SET_COOKIE, access_token_cookie);
    res.append_header(SET_COOKIE, id_token_cookie);
    res.append_header(SET_COOKIE, code_verifier_cookie);
    res.append_header(SET_COOKIE, state_cookie);
    res
}
