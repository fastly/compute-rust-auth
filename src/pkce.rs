use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use hmac_sha256::Hash;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::iter;
const CUSTOM_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

pub fn rand_chars(length: usize) -> String {
    let mut rng = thread_rng();
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(length)
        .collect()
}

pub struct Pkce {
    pub code_verifier: String,
    pub code_challenge: String,
}

impl Pkce {
    /// The code verifier must have 43 to 128 chars.
    /// https://tools.ietf.org/html/rfc7636
    pub const LENGTH: usize = 43;

    pub fn new(code_challenge_method: &str) -> Self {
        let verifier = rand_chars(Self::LENGTH);
        let challenge = match code_challenge_method {
            "S256" => CUSTOM_ENGINE.encode(&Hash::hash(verifier.as_bytes())),
            _ => CUSTOM_ENGINE.encode(&verifier),
        };
        Self {
            code_verifier: verifier,
            code_challenge: challenge,
        }
    }
}
