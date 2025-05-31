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
