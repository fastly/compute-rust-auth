use std::collections::HashMap;

const COOKIE_ATTRIBUTES: &str = "Path=/; SameSite=Lax; Secure; HttpOnly";

// Returns the "__Secure-" cookie prefix in production, and "local-" in development.
pub fn get_cookie_prefix() -> &'static str {
    let fastly_service_version = std::env::var("FASTLY_SERVICE_VERSION").unwrap_or("0".to_string());
    if fastly_service_version == "0" {
        "local-"
    } else {
        "__Secure-"
    }
}

pub fn parse(cookie_string: &str) -> HashMap<&str, &str> {
    cookie_string
        .split("; ")
        .filter_map(|kv| {
            kv.find('=').map(|index| {
                let (key, value) = kv.split_at(index);
                let key = key.trim().trim_start_matches(get_cookie_prefix());
                let value = value[1..].trim();
                (key, value)
            })
        })
        .collect()
}

pub fn persistent(name: &str, value: &str, max_age: u32) -> String {
    format!(
        "{}{}={}; Max-Age={}; {}",
        get_cookie_prefix(),
        name,
        value,
        max_age,
        COOKIE_ATTRIBUTES
    )
}

pub fn expired(name: &str) -> String {
    persistent(name, "expired", 0)
}

pub fn session(name: &str, value: &str) -> String {
    format!(
        "{}{}={}; {}",
        get_cookie_prefix(),
        name,
        value,
        COOKIE_ATTRIBUTES
    )
}
