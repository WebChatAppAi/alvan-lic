//! # alvan-lic
//!
//! A Rust crate for generating and validating time-based license keys with offline validation.
//!
//! ## Features
//! - Generate license keys with custom expiration times
//! - Validate license keys offline using HMAC
//! - Keys always start with "alvan-"
//! - Secure against tampering using cryptographic signatures
//!
//! ## Example
//! ```rust
//! use alvan_lic::{LicenseGenerator, LicenseValidator};
//!
//! // Create a generator with your secret key
//! let secret_key = "your-super-secret-key";
//! let generator = LicenseGenerator::new(secret_key);
//!
//! // Generate a license valid for 24 hours
//! let license_key = generator.generate_key(24).unwrap();
//! println!("Generated license: {}", license_key);
//!
//! // Validate the license
//! let validator = LicenseValidator::new(secret_key);
//! match validator.validate_key(&license_key) {
//!     Ok(info) => println!("License is valid until: {}", info.expires_at),
//!     Err(e) => println!("License validation failed: {}", e),
//! }
//! ```

mod error;
mod generator;
mod validator;

pub use error::{LicenseError, Result};
pub use generator::LicenseGenerator;
pub use validator::{LicenseInfo, LicenseValidator};

/// The prefix for all license keys
pub const LICENSE_PREFIX: &str = "alvan-";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_generation_and_validation() {
        let secret = "test-secret-key";
        let generator = LicenseGenerator::new(secret);
        let validator = LicenseValidator::new(secret);

        // Generate a license valid for 1 hour
        let license = generator.generate_key(1).unwrap();
        assert!(license.starts_with(LICENSE_PREFIX));

        // Validate the license
        let info = validator.validate_key(&license).unwrap();
        assert!(info.is_valid);
        assert!(info.hours_remaining > 0.0);
    }

    #[test]
    fn test_invalid_secret_key() {
        let generator = LicenseGenerator::new("secret1");
        let validator = LicenseValidator::new("secret2");

        let license = generator.generate_key(1).unwrap();
        let result = validator.validate_key(&license);
        
        assert!(result.is_err());
    }
}
