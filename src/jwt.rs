use crate::config::Config;
use fastly::Error;
use jwt_compact_preview::{
    alg::{Rs256, RsaVerifyingKey},
    prelude::*,
    ValidationError,
};
use serde::Deserialize;
use std::convert::TryFrom;

#[derive(PartialEq, Deserialize)]
pub struct CustomClaims {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud")]
    audience: String,
    // Add other custom JWT claims here.
    // You can see a full list of reserved claims at the IANA JSON Web Token Claims Registry: https://www.iana.org/assignments/jwt/jwt.xhtml#claims
}

// Validates a JWT signed with RS256, and verify its claims. Panics for an invalid token.
pub fn validate_token_rs256(token_string: &str, settings: &Config) -> Result<(), Error> {
    let token = UntrustedToken::try_from(token_string)?;
    // Ensure the algorithm used to sign the token is compatible with the validation function.
    if token.algorithm() != "RS256" {
        return Err(ValidationError::AlgorithmMismatch.into());
    }
    // Calculate the public key used to sign the token.
    let key = settings
        .jwks
        .keys
        .iter()
        .find(|&k| k.key_id == token.header().key_id.as_ref().unwrap().to_string())
        .unwrap();
    let modulus = base64::decode_config(&key.modulus, base64::URL_SAFE_NO_PAD)?;
    let exponent = base64::decode_config(&key.exponent, base64::URL_SAFE_NO_PAD)?;
    let verifying_key = RsaVerifyingKey::from_components(&modulus, &exponent)?;
    // Validate the token's integrity.
    let token: Token<CustomClaims> = Rs256.validate_integrity(&token, &verifying_key)?;
    // Validate the token's claims.
    token.claims().validate_expiration(TimeOptions::default())?;
    if (token.claims().custom.issuer != settings.openid_configuration.issuer)
        || (token.claims().custom.audience != settings.config.client_id)
    {
        return Err(ValidationError::NoClaim.into());
    }
    Ok(())
}
