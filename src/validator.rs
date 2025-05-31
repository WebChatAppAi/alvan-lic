//! License key validation functionality

use crate::{
    error::{LicenseError, Result},
    LICENSE_PREFIX,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Information about a validated license
#[derive(Debug, Clone)]
pub struct LicenseInfo {
    /// Whether the license is currently valid
    pub is_valid: bool,
    /// When the license was issued
    pub issued_at: DateTime<Utc>,
    /// When the license expires
    pub expires_at: DateTime<Utc>,
    /// Hours remaining until expiration (0 if expired)
    pub hours_remaining: f64,
}

/// License key validator for offline validation
pub struct LicenseValidator {
    secret_key: String,
}

impl LicenseValidator {
    /// Create a new license validator with the provided secret key
    ///
    /// # Arguments
    /// * `secret_key` - The same secret key used for generation
    ///
    /// # Example
    /// ```rust
    /// use alvan_lic::LicenseValidator;
    /// let validator = LicenseValidator::new("my-secret-key");
    /// ```
    pub fn new<S: Into<String>>(secret_key: S) -> Self {
        Self {
            secret_key: secret_key.into(),
        }
    }

    /// Validate a license key
    ///
    /// # Arguments
    /// * `license_key` - The license key to validate
    ///
    /// # Returns
    /// `LicenseInfo` if the license is valid, or an error
    ///
    /// # Example
    /// ```rust
    /// use alvan_lic::{LicenseGenerator, LicenseValidator};
    /// 
    /// let secret = "secret-key";
    /// let generator = LicenseGenerator::new(secret);
    /// let validator = LicenseValidator::new(secret);
    /// 
    /// let license = generator.generate_key(24).unwrap();
    /// let info = validator.validate_key(&license).unwrap();
    /// assert!(info.is_valid);
    /// ```
    pub fn validate_key(&self, license_key: &str) -> Result<LicenseInfo> {
        self.validate_key_at_time(license_key, Utc::now())
    }

    /// Validate a license key at a specific time (useful for testing)
    pub fn validate_key_at_time(
        &self,
        license_key: &str,
        current_time: DateTime<Utc>,
    ) -> Result<LicenseInfo> {
        // Check prefix
        if !license_key.starts_with(LICENSE_PREFIX) {
            return Err(LicenseError::InvalidFormat);
        }

        // Remove prefix and decode
        let encoded = &license_key[LICENSE_PREFIX.len()..];
        let data = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| LicenseError::Base64Error(e))?;

        // Find the separator
        let separator_pos = data
            .iter()
            .position(|&b| b == b'.')
            .ok_or(LicenseError::InvalidFormat)?;

        // Split payload and signature
        let payload = &data[..separator_pos];
        let provided_signature = &data[separator_pos + 1..];

        // Verify signature
        let mut mac = HmacSha256::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload);
        
        mac.verify_slice(provided_signature)
            .map_err(|_| LicenseError::InvalidSignature)?;

        // Parse payload
        let payload_str = String::from_utf8(payload.to_vec())
            .map_err(|e| LicenseError::InvalidData(e.to_string()))?;
        
        let parts: Vec<&str> = payload_str.split(':').collect();
        if parts.len() != 2 {
            return Err(LicenseError::InvalidFormat);
        }

        let issued_timestamp = parts[0]
            .parse::<i64>()
            .map_err(|e| LicenseError::InvalidData(e.to_string()))?;
        let expires_timestamp = parts[1]
            .parse::<i64>()
            .map_err(|e| LicenseError::InvalidData(e.to_string()))?;

        let issued_at = DateTime::from_timestamp(issued_timestamp, 0)
            .ok_or_else(|| LicenseError::InvalidData("Invalid issued timestamp".to_string()))?;
        let expires_at = DateTime::from_timestamp(expires_timestamp, 0)
            .ok_or_else(|| LicenseError::InvalidData("Invalid expires timestamp".to_string()))?;

        // Check if expired
        let is_valid = current_time < expires_at;
        let hours_remaining = if is_valid {
            (expires_at - current_time).num_minutes() as f64 / 60.0
        } else {
            0.0
        };

        if !is_valid {
            return Err(LicenseError::Expired);
        }

        Ok(LicenseInfo {
            is_valid,
            issued_at,
            expires_at,
            hours_remaining,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LicenseGenerator;
    use chrono::Duration;

    #[test]
    fn test_validate_valid_key() {
        let secret = "test-secret";
        let generator = LicenseGenerator::new(secret);
        let validator = LicenseValidator::new(secret);

        let key = generator.generate_key(24).unwrap();
        let info = validator.validate_key(&key).unwrap();

        assert!(info.is_valid);
        assert!(info.hours_remaining > 23.0);
        assert!(info.hours_remaining <= 24.0);
    }

    #[test]
    fn test_validate_expired_key() {
        let secret = "test-secret";
        let generator = LicenseGenerator::new(secret);
        let validator = LicenseValidator::new(secret);

        // Generate a key that expired 2 hours ago
        let past_time = Utc::now() - Duration::hours(3);
        let key = generator.generate_key_with_timestamp(1, past_time).unwrap();
        
        let result = validator.validate_key(&key);
        assert!(matches!(result, Err(LicenseError::Expired)));
    }

    #[test]
    fn test_validate_wrong_secret() {
        let generator = LicenseGenerator::new("secret1");
        let validator = LicenseValidator::new("secret2");

        let key = generator.generate_key(24).unwrap();
        let result = validator.validate_key(&key);
        
        assert!(matches!(result, Err(LicenseError::InvalidSignature)));
    }

    #[test]
    fn test_validate_tampered_key() {
        let secret = "test-secret";
        let generator = LicenseGenerator::new(secret);
        let validator = LicenseValidator::new(secret);

        let mut key = generator.generate_key(24).unwrap();
        // Tamper with the key
        key.push('X');
        
        let result = validator.validate_key(&key);
        assert!(result.is_err());
    }
}
