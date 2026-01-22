//! Speed test module
//!
//! Measures download and upload speeds by transferring data to/from test servers.

use color_eyre::Result;
use std::time::Instant;

/// Result of a speed test
#[derive(Debug, Clone)]
pub struct SpeedTestResult {
    pub download_mbps: f64,
    pub upload_mbps: f64,
}

/// Run a speed test and return download/upload speeds in Mbps
/// This runs blocking HTTP requests in a separate thread to avoid Tokio conflicts.
pub fn run_speed_test() -> Result<SpeedTestResult> {
    // Run the blocking speed test in a separate thread
    let handle = std::thread::spawn(run_speed_test_blocking);
    handle
        .join()
        .map_err(|_| color_eyre::eyre::eyre!("Speed test thread panicked"))?
}

/// Internal blocking implementation of speed test
fn run_speed_test_blocking() -> Result<SpeedTestResult> {
    let download = measure_download_speed()?;
    let upload = measure_upload_speed()?;

    Ok(SpeedTestResult {
        download_mbps: download,
        upload_mbps: upload,
    })
}

/// Measure download speed for approximately 5 seconds
fn measure_download_speed() -> Result<f64> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Use Cloudflare's speed test endpoint
    // Download for ~5 seconds by fetching multiple chunks
    let test_url = "https://speed.cloudflare.com/__down?bytes=5000000"; // 5MB per request

    let start = Instant::now();
    let mut total_bytes = 0usize;
    let target_duration = std::time::Duration::from_secs(5);

    // Keep downloading until 5 seconds elapsed
    while start.elapsed() < target_duration {
        let response = client.get(test_url).send();

        if let Ok(resp) = response {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes() {
                    total_bytes += bytes.len();
                }
            }
        } else {
            break; // Stop on error
        }
    }

    let duration = start.elapsed();
    if total_bytes == 0 || duration.as_secs_f64() < 0.1 {
        return Ok(0.0);
    }

    // Calculate speed in Mbps (megabits per second)
    let bytes_per_sec = total_bytes as f64 / duration.as_secs_f64();
    let mbps = (bytes_per_sec * 8.0) / 1_000_000.0;

    Ok(mbps)
}

/// Measure upload speed for approximately 5 seconds
fn measure_upload_speed() -> Result<f64> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Create a 1MB payload for upload test
    let payload = vec![0u8; 1_000_000]; // 1MB per request

    // Use Cloudflare's speed test upload endpoint
    let test_url = "https://speed.cloudflare.com/__up";

    let start = Instant::now();
    let mut total_bytes = 0usize;
    let target_duration = std::time::Duration::from_secs(5);

    // Keep uploading until 5 seconds elapsed
    while start.elapsed() < target_duration {
        let response = client.post(test_url).body(payload.clone()).send();

        if let Ok(resp) = response {
            if resp.status().is_success() || resp.status().as_u16() == 411 {
                total_bytes += payload.len();
            }
        } else {
            break; // Stop on error
        }
    }

    let duration = start.elapsed();
    if total_bytes == 0 || duration.as_secs_f64() < 0.1 {
        return Ok(0.0);
    }

    // Calculate speed in Mbps
    let bytes_per_sec = total_bytes as f64 / duration.as_secs_f64();
    let mbps = (bytes_per_sec * 8.0) / 1_000_000.0;

    Ok(mbps)
}

/// Run just the download portion of the speed test (in separate thread)
pub fn measure_download_only() -> Result<f64> {
    let handle = std::thread::spawn(measure_download_speed);
    handle
        .join()
        .map_err(|_| color_eyre::eyre::eyre!("Download test thread panicked"))?
}

/// Run just the upload portion of the speed test (in separate thread)
pub fn measure_upload_only() -> Result<f64> {
    let handle = std::thread::spawn(measure_upload_speed);
    handle
        .join()
        .map_err(|_| color_eyre::eyre::eyre!("Upload test thread panicked"))?
}

#[cfg(test)]
mod tests {
    // Speed tests require network access, so we skip them in unit tests
    // They can be tested manually
}
