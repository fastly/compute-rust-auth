use fastly::{ConfigStore, SecretStore};
use serde::Deserialize;

pub const IDP_BACKEND_NAME: &str = "idp";
pub const ORIGIN_BACKEND_NAME: &str = "origin";

const STATE_PARAMETER_LENGTH: usize = 10;

#[derive(Deserialize, Default)]
pub struct ServiceConfiguration {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub nonce_secret: String,
    pub introspect_access_token: bool,
    pub jwt_access_token: bool,
    pub callback_path: String,
    pub code_challenge_method: String,
    pub state_parameter_length: usize,
    pub scope: String,
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
    #[allow(dead_code)]
    #[serde(default)]
    pub issuer: String,
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
    pub fn load() -> Result<Self, fastly::Error> {
        let secrets =
            SecretStore::open("oauth_secrets").expect("Could not open oauth_secrets secret store");

        let get_secret = |key: &str| {
            secrets.get(key).map(|secret| {
                std::str::from_utf8(&secret.plaintext())
                    .unwrap()
                    .to_string()
            })
        };

        let require_secret = |key: &str| {
            get_secret(key).unwrap_or_else(|| panic!("Required secret {} not found", key))
        };

        let cfg = ConfigStore::open("oauth_config");
        let jwks = cfg.get("jwks").expect("JWKS metadata not found");
        let openid_config = cfg
            .get("openid_configuration")
            .expect("OIDC metadata not found");

        let value_or = |key: &str, default: &str| cfg.get(key).unwrap_or(default.to_string());

        let value_or_false = |key: &str| match cfg.get(key) {
            Some(val) => val.parse::<bool>().unwrap_or_default(),
            _ => false,
        };

        Ok(Self {
            config: ServiceConfiguration {
                client_id: require_secret("client_id"),
                client_secret: get_secret("client_secret"),
                nonce_secret: require_secret("nonce_secret"),
                callback_path: value_or("callback_path", "/callback"),
                scope: value_or("scope", "openid"),
                code_challenge_method: value_or("code_challenge_method", "S256"),
                introspect_access_token: value_or_false("introspect_access_token"),
                jwt_access_token: value_or_false("jwt_access_token"),
                state_parameter_length: STATE_PARAMETER_LENGTH,
            },
            jwks: serde_json::from_str(&jwks).unwrap(),
            openid_configuration: serde_json::from_str(&openid_config).unwrap(),
        })
    }
}
