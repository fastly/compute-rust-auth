use serde::{Deserialize, Serialize};

#[derive(Deserialize, Default)]
pub struct CallbackQueryParameters {
    pub code: String,
    pub state: String,
}

#[derive(Deserialize, Default)]
pub struct AuthorizeResponse {
    pub access_token: String,
    pub id_token: String,
    pub expires_in: u32,
}

#[derive(Serialize)]
pub struct ExchangePayload<'a> {
    pub client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<&'a str>,
    pub code: &'a str,
    pub grant_type: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
}

#[derive(Serialize)]
pub struct AuthCodePayload<'a> {
    pub client_id: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub redirect_uri: &'a str,
    pub response_type: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
}
