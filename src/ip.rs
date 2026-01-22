//! IP address retrieval module
//!
//! Provides functions to get local and public IP addresses.

use color_eyre::Result;

/// Get the local IP address assigned by the router
pub fn get_local_ip() -> Result<String> {
    let ip = local_ip_address::local_ip()?;
    Ok(ip.to_string())
}

/// Get the public IP address visible to the internet (blocking version)
/// Note: This must NOT be called from within an async context.
/// Use get_public_ip_blocking() wrapped in spawn_blocking instead.
fn get_public_ip_blocking() -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Use ipify.org - simple API that returns just the IP
    let response = client.get("https://api.ipify.org").send()?;

    if response.status().is_success() {
        let ip = response.text()?;
        Ok(ip.trim().to_string())
    } else {
        // Fallback to alternative service
        let response = client.get("https://icanhazip.com").send()?;
        let ip = response.text()?;
        Ok(ip.trim().to_string())
    }
}

/// Get the public IP address (safe to call from async context)
pub fn get_public_ip() -> Option<String> {
    // Use std::thread for blocking HTTP call to avoid Tokio runtime conflicts
    let handle = std::thread::spawn(get_public_ip_blocking);
    handle.join().ok().and_then(|r| r.ok())
}

/// Get both local and public IPs (safe to call from async context)
pub fn get_all_ips() -> (Option<String>, Option<String>) {
    let local = get_local_ip().ok();
    // Spawn public IP fetch in a separate thread to avoid blocking Tokio
    let public = get_public_ip();
    (local, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_local_ip() {
        let result = get_local_ip();
        // Local IP should always work
        assert!(result.is_ok());
        let ip = result.unwrap();
        // Should be a valid IP format
        assert!(ip.contains('.') || ip.contains(':'));
    }

    // Note: Public IP test skipped as it requires network access
}
