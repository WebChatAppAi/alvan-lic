//! License key generation functionality

use crate::{error::Result, LICENSE_PREFIX};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// License key generator that creates time-based license keys
pub struct LicenseGenerator {
    secret_key: String,
}

impl LicenseGenerator {
    /// Create a new license generator with the provided secret key
    ///
    /// # Arguments
    /// * `secret_key` - A secret key used for HMAC signing
    ///
    /// # Example
    /// ```rust
    /// use alvan_lic::LicenseGenerator;
    /// let generator = LicenseGenerator::new("my-secret-key");
    /// ```
    pub fn new<S: Into<String>>(secret_key: S) -> Self {
        Self {
            secret_key: secret_key.into(),
        }
    }

    /// Generate a license key valid for the specified number of hours
    ///
    /// # Arguments
    /// * `hours` - Number of hours the license should be valid
    ///
    /// # Returns
    /// A license key string starting with "alvan-"
    ///
    /// # Example
    /// ```rust
    /// use alvan_lic::LicenseGenerator;
    /// let generator = LicenseGenerator::new("secret");
    /// let license = generator.generate_key(24).unwrap(); // Valid for 24 hours
    /// ```
    pub fn generate_key(&self, hours: u64) -> Result<String> {
        self.generate_key_with_timestamp(hours, Utc::now())
    }

    /// Generate a license key with a custom timestamp (useful for testing)
    pub fn generate_key_with_timestamp(
        &self,
        hours: u64,
        issued_at: DateTime<Utc>,
    ) -> Result<String> {
        // Calculate expiration time
        let expires_at = issued_at + Duration::hours(hours as i64);

        // Create the payload
        let payload = format!("{}:{}", issued_at.timestamp(), expires_at.timestamp());

        // Create HMAC signature
        let mut mac = HmacSha256::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();

        // Combine payload and signature
        let mut data = Vec::new();
        data.extend_from_slice(payload.as_bytes());
        data.push(b'.');
        data.extend_from_slice(&signature);

        // Encode to base64
        let encoded = URL_SAFE_NO_PAD.encode(&data);

        // Add prefix
        Ok(format!("{}{}", LICENSE_PREFIX, encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let generator = LicenseGenerator::new("test-secret");
        let key = generator.generate_key(24).unwrap();
        
        assert!(key.starts_with(LICENSE_PREFIX));
        assert!(key.len() > LICENSE_PREFIX.len());
    }

    #[test]
    fn test_different_hours() {
        let generator = LicenseGenerator::new("test-secret");
        let key1 = generator.generate_key(1).unwrap();
        let key24 = generator.generate_key(24).unwrap();
        let key_year = generator.generate_key(24 * 365).unwrap();
        
        // All should start with prefix
        assert!(key1.starts_with(LICENSE_PREFIX));
        assert!(key24.starts_with(LICENSE_PREFIX));
        assert!(key_year.starts_with(LICENSE_PREFIX));
        
        // Keys should be different
        assert_ne!(key1, key24);
        assert_ne!(key24, key_year);
    }
}
