use fastly::ConfigStore;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(default)]
pub struct ServiceConfiguration {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub introspect_access_token: bool,
    pub jwt_access_token: bool,
    pub callback_path: String,
    pub code_challenge_method: String,
    pub state_parameter_length: usize,
    pub scope: String,
    pub nonce_secret: String,
}

impl Default for ServiceConfiguration {
    fn default() -> Self {
        Self {
            client_id: "".to_string(),
            client_secret: None,
            introspect_access_token: false,
            jwt_access_token: false,
            callback_path: "/callback".to_string(),
            code_challenge_method: "S256".to_string(),
            state_parameter_length: 10,
            scope: "openid".to_string(),
            nonce_secret: "".to_string(),
        }
    }
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
    pub fn load() -> Result<Self, fastly::Error> {
        let cfg = ConfigStore::open("config");
        let jwks: String = cfg.get("jwks").expect("JWKS metadata not found");
        let openid_config: String = cfg
            .get("openid_configuration")
            .expect("OIDC metadata not found");

        Ok(Self {
            config: toml::from_str(include_str!("config.toml")).unwrap(),
            jwks: serde_json::from_str(&jwks).unwrap(),
            openid_configuration: serde_json::from_str(&openid_config).unwrap(),
        })
    }
}
