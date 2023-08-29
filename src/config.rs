use serde::Deserialize;

#[derive(Deserialize)]
#[serde(default)]
pub struct ServiceConfiguration<'a> {
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub introspect_access_token: bool,
    pub jwt_access_token: bool,
    pub callback_path: &'a str,
    pub code_challenge_method: &'a str,
    pub state_parameter_length: usize,
    pub scope: String,
    pub nonce_secret: &'a str,
}

impl Default for ServiceConfiguration<'static> {
    fn default() -> Self {
        Self {
            client_id: "",
            client_secret: None,
            introspect_access_token: false,
            jwt_access_token: false,
            callback_path: "/callback",
            code_challenge_method: "S256",
            state_parameter_length: 10,
            scope: "openid".to_string(),
            nonce_secret: "",
        }
    }
}

#[derive(Deserialize, Default)]
pub struct OpenIdConfiguration<'a> {
    pub issuer: &'a str,
    pub authorization_endpoint: &'a str,
    pub token_endpoint: &'a str,
    pub userinfo_endpoint: &'a str,
}

#[derive(Deserialize, Default)]
pub struct JsonWebKey<'a> {
    #[serde(rename = "kid")]
    pub key_id: &'a str,
    #[serde(rename = "e")]
    pub exponent: &'a str,
    #[serde(rename = "n")]
    pub modulus: &'a str,
    pub issuer: &'a str,
}

#[derive(Deserialize, Default)]
pub struct Jwks<'a> {
    #[serde(borrow)]
    pub keys: Vec<JsonWebKey<'a>>,
}

#[derive(Deserialize, Default)]
pub struct Config {
    #[serde(borrow)]
    pub config: ServiceConfiguration<'static>,
    #[serde(borrow)]
    pub jwks: Jwks<'static>,
    #[serde(borrow)]
    pub openid_configuration: OpenIdConfiguration<'static>,
}

impl Config {
    pub fn load() -> Self {
        Self {
            config: toml::from_str(include_str!("config.toml")).unwrap(),
            jwks: serde_json::from_str(include_str!("well-known/jwks.json")).unwrap(),
            openid_configuration: serde_json::from_str(include_str!(
                "well-known/openid-configuration.json"
            ))
            .unwrap(),
        }
    }
}
