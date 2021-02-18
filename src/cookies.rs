use std::collections::HashMap;

const COOKIE_ATTRIBUTES: &str = "Path=/; SameSite=Lax; Secure; HttpOnly";

pub fn parse(cookie_string: &str) -> HashMap<String, String> {
    cookie_string
        .split("; ")
        .filter_map(|kv| {
            kv.find("=").map(|index| {
                let (key, value) = kv.split_at(index);
                let key = key.to_string();
                let value = value[1..].to_string();
                (key, value)
            })
        })
        .collect()
}

pub fn permanent(name: &str, value: &str, max_age: u32) -> String {
    format!(
        "{}={}; Max-Age={}; {}",
        name, value, max_age, COOKIE_ATTRIBUTES
    )
}

pub fn expired(name: &str) -> String {
    permanent(name, "expired", 0)
}

pub fn session(name: &str, value: &str) -> String {
    format!("{}={}; {}", name, value, COOKIE_ATTRIBUTES)
}
