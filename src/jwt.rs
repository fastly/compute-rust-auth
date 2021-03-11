use crate::config::Config;
use fastly::error::bail;
use fastly::Error;
use jwt_simple::prelude::*;

// Validates a JWT signed with RS256, and verify its claims. Panics for an invalid token.
pub fn validate_token_rs256(token_string: &str, settings: &Config) -> Result<JWTClaims<NoCustomClaims>, Error> {
    let metadata = Token::decode_metadata(&token_string)?;
    // Match the public key id for the JSON web key.
    match settings.jwks.keys.iter().find(|&k| k.key_id == metadata.key_id().unwrap()) {
        Some(key) => {
            // Reconstruct the public key used to sign the token.
            let modulus = base64::decode_config(&key.modulus, base64::URL_SAFE_NO_PAD)?;
            let exponent = base64::decode_config(&key.exponent, base64::URL_SAFE_NO_PAD)?;
            let public_key = RS256PublicKey::from_components(&modulus, &exponent)?;
            // Validate the token's claims.
            let mut verification_options = VerificationOptions::default();
            verification_options.allowed_issuers = Some(HashSet::from_strings(&[settings
                .openid_configuration
                .issuer]));
            verification_options.allowed_audiences =
                Some(HashSet::from_strings(&[settings.config.client_id]));

            public_key
                .verify_token::<NoCustomClaims>(&token_string, Some(verification_options))
        }
        _ => bail!("Invalid public key."),
    }
}
