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
        license.replace('a', "b"),
        format!("{}X", license),
        license[..license.len()-1].to_string(),
        "alvan-completely-fake-license".to_string(),
    ];
    
    for tampered in tampered_licenses {
        assert!(validator.validate_key(&tampered).is_err());
    }
}
