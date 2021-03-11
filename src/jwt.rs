use crate::config::Config;
use fastly::Error;
use jwt_simple::prelude::*;

// Validates a JWT signed with RS256, and verifies its claims.
pub fn validate_token_rs256(
    token_string: &str,
    settings: &Config,
) -> Result<JWTClaims<NoCustomClaims>, Error> {
    // Peek at the token metadata before verification and retrieve the key identifier,
    // in order to pick the right key out of the JWK set.
    let metadata = Token::decode_metadata(&token_string)?;
    let key_id = metadata.key_id().unwrap();
    // Match the public key id for the JSON web key.
    let key_metadata = settings
        .jwks
        .keys
        .iter()
        .find(|&k| k.key_id == key_id)
        .unwrap();
    // Reconstruct the public key used to sign the token.
    let modulus = base64::decode_config(&key_metadata.modulus, base64::URL_SAFE_NO_PAD)?;
    let exponent = base64::decode_config(&key_metadata.exponent, base64::URL_SAFE_NO_PAD)?;
    let public_key = RS256PublicKey::from_components(&modulus, &exponent)?;
    // Verify the token's claims.
    let mut verification_options = VerificationOptions::default();
    verification_options.allowed_issuers = Some(HashSet::from_strings(&[settings
        .openid_configuration
        .issuer]));
    verification_options.allowed_audiences =
        Some(HashSet::from_strings(&[settings.config.client_id]));
    // Custom claims verification is also supported – https://docs.rs/jwt-simple/0.9.3/jwt_simple/index.html#custom-claims
    public_key.verify_token::<NoCustomClaims>(&token_string, Some(verification_options))
}
