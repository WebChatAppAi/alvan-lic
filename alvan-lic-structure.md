# alvan-lic Project Structure

```
alvan-lic/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── generator.rs
│   ├── validator.rs
│   └── error.rs
├── examples/
│   └── basic_usage.rs
└── tests/
    └── integration_test.rs
```

## File Contents

### Cargo.toml
```toml
[package]
name = "alvan-lic"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "A Rust crate for generating and validating time-based license keys with offline validation"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourusername/alvan-lic"
keywords = ["license", "key", "validation", "generator", "offline"]
categories = ["authentication", "cryptography"]
readme = "README.md"

[dependencies]
hmac = "0.12"
sha2 = "0.10"
base64 = "0.21"
chrono = "0.4"
thiserror = "1.0"

[dev-dependencies]
tokio = { version = "1", features = ["full"] }

[[example]]
name = "basic_usage"
```

### src/lib.rs
```rust
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
```

### src/error.rs
```rust
//! Error types for the alvan-lic crate

use thiserror::Error;

/// Result type alias for license operations
pub type Result<T> = std::result::Result<T, LicenseError>;

/// Errors that can occur during license generation or validation
#[derive(Error, Debug)]
pub enum LicenseError {
    /// The license key has an invalid format
    #[error("Invalid license format")]
    InvalidFormat,

    /// The license key signature is invalid
    #[error("Invalid license signature")]
    InvalidSignature,

    /// The license has expired
    #[error("License has expired")]
    Expired,

    /// The license data is corrupted or invalid
    #[error("Invalid license data: {0}")]
    InvalidData(String),

    /// Base64 decoding error
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Chrono parsing error
    #[error("Time parsing error: {0}")]
    ChronoError(#[from] chrono::ParseError),
}
```

### src/generator.rs
```rust
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
    pub(crate) fn generate_key_with_timestamp(
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
```

### src/validator.rs
```rust
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
    pub(crate) fn validate_key_at_time(
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
```

### examples/basic_usage.rs
```rust
//! Basic usage example for alvan-lic

use alvan_lic::{LicenseGenerator, LicenseValidator};

fn main() {
    // IMPORTANT: Use a strong, randomly generated secret key in production!
    // This is just an example. Store your secret key securely.
    let secret_key = "your-super-secret-key-change-this-in-production";

    // Create a license generator
    let generator = LicenseGenerator::new(secret_key);

    // Generate licenses with different durations
    println!("Generating licenses...\n");

    // 1 hour license
    let license_1h = generator.generate_key(1).unwrap();
    println!("1 hour license: {}", license_1h);

    // 24 hour license
    let license_24h = generator.generate_key(24).unwrap();
    println!("24 hour license: {}", license_24h);

    // 30 day license (720 hours)
    let license_30d = generator.generate_key(720).unwrap();
    println!("30 day license: {}", license_30d);

    // 1 year license (8760 hours)
    let license_1y = generator.generate_key(8760).unwrap();
    println!("1 year license: {}", license_1y);

    // Create a validator with the same secret key
    let validator = LicenseValidator::new(secret_key);

    println!("\nValidating licenses...\n");

    // Validate the 24 hour license
    match validator.validate_key(&license_24h) {
        Ok(info) => {
            println!("License validation successful!");
            println!("  Valid: {}", info.is_valid);
            println!("  Issued at: {}", info.issued_at);
            println!("  Expires at: {}", info.expires_at);
            println!("  Hours remaining: {:.2}", info.hours_remaining);
        }
        Err(e) => {
            println!("License validation failed: {}", e);
        }
    }

    // Example of validation with wrong secret key
    println!("\nTrying validation with wrong secret key...");
    let wrong_validator = LicenseValidator::new("wrong-secret-key");
    match wrong_validator.validate_key(&license_24h) {
        Ok(_) => println!("This shouldn't happen!"),
        Err(e) => println!("Expected error: {}", e),
    }

    // Example of invalid license format
    println!("\nTrying validation with invalid license...");
    match validator.validate_key("invalid-license-key") {
        Ok(_) => println!("This shouldn't happen!"),
        Err(e) => println!("Expected error: {}", e),
    }
}
```

### tests/integration_test.rs
```rust
//! Integration tests for alvan-lic

use alvan_lic::{LicenseGenerator, LicenseValidator};
use chrono::{Duration, Utc};

#[test]
fn test_full_workflow() {
    let secret = "integration-test-secret";
    let generator = LicenseGenerator::new(secret);
    let validator = LicenseValidator::new(secret);

    // Generate multiple licenses
    let licenses = vec![
        generator.generate_key(1).unwrap(),
        generator.generate_key(24).unwrap(),
        generator.generate_key(168).unwrap(), // 1 week
        generator.generate_key(8760).unwrap(), // 1 year
    ];

    // All should be valid
    for license in &licenses {
        let info = validator.validate_key(license).unwrap();
        assert!(info.is_valid);
        assert!(info.hours_remaining > 0.0);
    }
}

#[test]
fn test_license_format() {
    let generator = LicenseGenerator::new("test-secret");
    
    for hours in [1, 10, 100, 1000, 10000] {
        let license = generator.generate_key(hours).unwrap();
        assert!(license.starts_with("alvan-"));
        assert!(license.len() > 10); // Should have substantial content
    }
}

#[test]
fn test_security() {
    let secret1 = "secret-key-1";
    let secret2 = "secret-key-2";
    
    let gen1 = LicenseGenerator::new(secret1);
    let gen2 = LicenseGenerator::new(secret2);
    
    let val1 = LicenseValidator::new(secret1);
    let val2 = LicenseValidator::new(secret2);
    
    // Generate with secret1
    let license = gen1.generate_key(24).unwrap();
    
    // Should validate with secret1
    assert!(val1.validate_key(&license).is_ok());
    
    // Should NOT validate with secret2
    assert!(val2.validate_key(&license).is_err());
    
    // Generate with secret2
    let license2 = gen2.generate_key(24).unwrap();
    
    // Should validate with secret2
    assert!(val2.validate_key(&license2).is_ok());
    
    // Should NOT validate with secret1
    assert!(val1.validate_key(&license2).is_err());
}

#[test]
fn test_expiration() {
    let secret = "test-secret";
    let generator = LicenseGenerator::new(secret);
    let validator = LicenseValidator::new(secret);
    
    // Generate a key that's already expired
    let past = Utc::now() - Duration::hours(2);
    let expired_key = generator.generate_key_with_timestamp(1, past).unwrap();
    
    // Should fail validation
    let result = validator.validate_key(&expired_key);
    assert!(result.is_err());
}

#[test]
fn test_tampering_detection() {
    let secret = "test-secret";
    let generator = LicenseGenerator::new(secret);
    let validator = LicenseValidator::new(secret);
    
    let license = generator.generate_key(24).unwrap();
    
    // Various tampering attempts
    let tampered_licenses = vec![
        license.replace('a', 'b'),
        format!("{}X", license),
        license[..license.len()-1].to_string(),
        "alvan-completely-fake-license".to_string(),
    ];
    
    for tampered in tampered_licenses {
        assert!(validator.validate_key(&tampered).is_err());
    }
}
```

### README.md
```markdown
# alvan-lic

A Rust crate for generating and validating time-based license keys with offline validation.

## Features

- 🔐 **Secure**: Uses HMAC-SHA256 for cryptographic signing
- ⏱️ **Time-based**: Create licenses valid for any duration (hours)
- 🔌 **Offline**: No internet connection required for validation
- 🚀 **Fast**: Minimal dependencies and efficient implementation
- 🛡️ **Tamper-proof**: Any modification to the license key will invalidate it

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
alvan-lic = "0.1.0"
```

## Quick Start

```rust
use alvan_lic::{LicenseGenerator, LicenseValidator};

fn main() {
    // Use a strong secret key in production
    let secret_key = "your-super-secret-key";
    
    // Generate a license valid for 24 hours
    let generator = LicenseGenerator::new(secret_key);
    let license_key = generator.generate_key(24).unwrap();
    println!("License: {}", license_key);
    
    // Validate the license
    let validator = LicenseValidator::new(secret_key);
    match validator.validate_key(&license_key) {
        Ok(info) => {
            println!("Valid for {:.1} more hours", info.hours_remaining);
        }
        Err(e) => {
            println!("Invalid license: {}", e);
        }
    }
}
```

## Usage

### Generating License Keys

```rust
use alvan_lic::LicenseGenerator;

let generator = LicenseGenerator::new("secret-key");

// Generate different duration licenses
let one_hour = generator.generate_key(1).unwrap();
let one_day = generator.generate_key(24).unwrap();
let one_month = generator.generate_key(24 * 30).unwrap();
let one_year = generator.generate_key(24 * 365).unwrap();
```

### Validating License Keys

```rust
use alvan_lic::LicenseValidator;

let validator = LicenseValidator::new("secret-key");

match validator.validate_key(&license_key) {
    Ok(info) => {
        println!("License is valid!");
        println!("Issued: {}", info.issued_at);
        println!("Expires: {}", info.expires_at);
        println!("Hours remaining: {:.2}", info.hours_remaining);
    }
    Err(e) => {
        println!("License validation failed: {}", e);
    }
}
```

## Security Considerations

1. **Secret Key**: 
   - Use a strong, randomly generated secret key
   - Keep your secret key secure and never expose it
   - Use different secret keys for different applications

2. **Offline Validation**:
   - The same secret key must be used for generation and validation
   - Keys cannot be forged without knowing the secret key
   - Validation works completely offline

3. **Time Synchronization**:
   - Ensure system clocks are reasonably synchronized
   - Keys are validated against the system's current time

## License Format

All license keys start with `alvan-` followed by a base64-encoded payload and signature.

Example: `alvan-MTcwNDQ2NzI4MjoxNzA0NTUzNjgyLkPCt8K3w4Qpw6ZVwq0N...`

## Error Handling

The crate provides detailed error types:

- `InvalidFormat`: The license key format is incorrect
- `InvalidSignature`: The signature doesn't match (wrong secret key)
- `Expired`: The license has expired
- `InvalidData`: The license data is corrupted

## Examples

See the `examples/` directory for more detailed usage examples.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
```