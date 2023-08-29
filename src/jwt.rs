use crate::config::Config;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use fastly::Error;
use hmac_sha256::Hash;
use jwt_simple::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
const CUSTOM_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

// Validates a JWT signed with RS256, and verifies its claims.
pub fn validate_token_rs256<CustomClaims: Serialize + DeserializeOwned>(
    token_string: &str,
    settings: &Config,
) -> Result<JWTClaims<CustomClaims>, Error> {
    // Peek at the token metadata before verification and retrieve the key identifier,
    // in order to pick the right key out of the JWK set.
    let metadata = Token::decode_metadata(token_string)?;
    let key_id = match metadata.key_id() {
        None => {
            return Err(Error::msg(
                "Failed to decode public key identifier for token",
            ))
        }
        Some(value) => value,
    };
    // Match the public key id for the JSON web key.
    let key_metadata = settings
        .jwks
        .keys
        .iter()
        .find(|&k| k.key_id == key_id)
        .unwrap();
    // Reconstruct the public key used to sign the token.
    let modulus = CUSTOM_ENGINE.decode(&key_metadata.modulus)?;
    let exponent = CUSTOM_ENGINE.decode(&key_metadata.exponent)?;
    let public_key = RS256PublicKey::from_components(&modulus, &exponent)?;
    // Verify the token's claims.
    // Custom claims are also supported – see https://docs.rs/jwt-simple/0.9.3/jwt_simple/index.html#custom-claims
    let verification_options = VerificationOptions {
        allowed_issuers: Some(HashSet::from_strings(&[
            key_metadata.issuer,
            settings.openid_configuration.issuer,
        ])),
        allowed_audiences: Some(HashSet::from_strings(&[settings.config.client_id])),
        ..Default::default()
    };
    public_key.verify_token::<CustomClaims>(token_string, Some(verification_options))
}

pub struct NonceToken {
    auth_key: HS256Key,
}

impl NonceToken {
    // Computes a HS256 key from the nonce secret.
    pub fn new(nonce_secret: &str) -> Self {
        Self {
            auth_key: HS256Key::from_bytes(&Hash::hash(nonce_secret.as_bytes())),
        }
    }
    // Creates a time-limited token and encodes the passed state within its claims.
    // Returns a tuple: (token, nonce)
    pub fn generate_from_state(&self, state: &str) -> (String, String) {
        // Create token claims valid for 5 minutes.
        let mut state_and_nonce_claim = Claims::create(Duration::from_mins(5)).with_subject(state);
        // Generate a random value (nonce) and attach it to the token.
        let nonce = state_and_nonce_claim.create_nonce();
        (
            self.auth_key.authenticate(state_and_nonce_claim).unwrap(),
            nonce,
        )
    }
    // Verifies the token and retrieves its subject claim, a state string.
    pub fn get_claimed_state(&self, state_and_nonce: &str) -> Option<String> {
        match &self
            .auth_key
            .verify_token::<NoCustomClaims>(state_and_nonce, None)
        {
            Ok(state_and_nonce_claim) => state_and_nonce_claim.subject.to_owned(),
            _ => None,
        }
    }
}
