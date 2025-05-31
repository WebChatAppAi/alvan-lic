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
