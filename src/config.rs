use serde::{Deserialize};

fn default_callback_path() -> String {
    "/callback".to_string()
}

fn default_code_challenge_method() -> String {
    "S256".to_string()
}

fn default_state_parameter_length() -> usize {
    10
}

fn default_to_false() -> bool {
    false
}

#[derive(Deserialize, Default)]
pub struct ServiceConfiguration {
    pub client_id: String,
    pub client_secret: Option<String>,
    #[serde(default = "default_to_false")]
    pub verify_access_token: bool,
    #[serde(default = "default_to_false")]
    pub jwt_access_token: bool,
    #[serde(default = "default_callback_path")]
    pub callback_path: String,
    #[serde(default = "default_code_challenge_method")]
    pub code_challenge_method: String,
    #[serde(default = "default_state_parameter_length")]
    pub state_parameter_length: usize,
}

#[derive(Deserialize, Default)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
}

#[derive(Deserialize, Default)]
pub struct JsonWebKey {
    #[serde(rename = "kid")]
    pub key_id: String,
    #[serde(rename = "e")]
    pub exponent: String,
    #[serde(rename = "n")]
    pub modulus: String,
}

#[derive(Deserialize, Default)]
pub struct Jwks {
    pub keys: Vec<JsonWebKey>,
}

#[derive(Deserialize, Default)]
pub struct Config {
    pub config: ServiceConfiguration,
    pub jwks: Jwks,
    pub openid_configuration: OpenIdConfiguration,
}

impl Config {
    pub fn load() -> Self {
        Self {
            config: toml::from_str(include_str!("config.toml")).unwrap(),
            jwks: serde_json::from_str(include_str!(".well-known/jwks.json")).unwrap(),
            openid_configuration: serde_json::from_str(include_str!(".well-known/openid-configuration.json")).unwrap(),
        }
    }
}
