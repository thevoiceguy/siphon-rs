use sip_core::Response;

/// Extract realm value from WWW-Authenticate/Proxy-Authenticate headers.
pub fn extract_realm(response: &Response) -> Option<String> {
    let header_val = response
        .headers
        .get("WWW-Authenticate")
        .or_else(|| response.headers.get("Proxy-Authenticate"))?;
    // crude parse: look for realm="..."
    header_val.split(',').find_map(|part| {
        let part = part.trim();
        if part.to_ascii_lowercase().starts_with("realm=") {
            part.split_once('=')
                .and_then(|(_, v)| v.trim_matches('"').to_owned().into())
        } else {
            None
        }
    })
}
