//! Interactive CLI tool for generating and validating license keys

use alvan_lic::{LicenseGenerator, LicenseValidator};
use std::io::{self, Write};

fn main() {
    println!("🔐 Alvan License Key Manager");
    println!("==============================");
    
    loop {
        println!("\nWhat would you like to do?");
        println!("1. Generate a new license key");
        println!("2. Validate an existing license key");
        println!("3. Exit");
        print!("\nEnter your choice (1-3): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => generate_key(),
            "2" => validate_key(),
            "3" => {
                println!("👋 Goodbye!");
                break;
            }
            _ => println!("❌ Invalid choice. Please enter 1, 2, or 3."),
        }
    }
}

fn generate_key() {
    println!("\n🔧 License Key Generation");
    println!("-------------------------");
    
    // Get secret key
    let secret_key = get_secret_key();
    
    // Get hours
    let hours = get_hours_input();
    
    // Generate the key
    let generator = LicenseGenerator::new(&secret_key);
    match generator.generate_key(hours) {
        Ok(license_key) => {
            println!("\n✅ License key generated successfully!");
            println!("📋 License Key: {}", license_key);
            println!("⏰ Valid for: {} hours", hours);
            println!("🔑 Secret used: {}", if secret_key == get_default_secret() { "default" } else { "custom" });
            
            // Calculate expiration time
            let now = chrono::Utc::now();
            let expires_at = now + chrono::Duration::hours(hours as i64);
            println!("📅 Expires at: {}", expires_at.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        Err(e) => {
            println!("❌ Failed to generate license key: {}", e);
        }
    }
}

fn validate_key() {
    println!("\n🔍 License Key Validation");
    println!("-------------------------");
    
    // Get the license key to validate
    print!("Enter the license key to validate: ");
    io::stdout().flush().unwrap();
    let mut license_key = String::new();
    io::stdin().read_line(&mut license_key).unwrap();
    let license_key = license_key.trim();
    
    if license_key.is_empty() {
        println!("❌ License key cannot be empty!");
        return;
    }
    
    // Get secret key
    let secret_key = get_secret_key();
    
    // Validate the key
    let validator = LicenseValidator::new(&secret_key);
    match validator.validate_key(license_key) {
        Ok(info) => {
            println!("\n✅ License key is VALID!");
            println!("📊 License Information:");
            println!("   📅 Issued at: {}", info.issued_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("   ⏰ Expires at: {}", info.expires_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("   🕒 Hours remaining: {:.2}", info.hours_remaining);
            println!("   ✅ Status: Active");
        }
        Err(e) => {
            println!("\n❌ License key validation FAILED!");
            match e {
                alvan_lic::LicenseError::Expired => {
                    println!("   🕒 Reason: License has expired");
                }
                alvan_lic::LicenseError::InvalidSignature => {
                    println!("   🔑 Reason: Invalid signature (wrong secret key or tampered key)");
                }
                alvan_lic::LicenseError::InvalidFormat => {
                    println!("   📝 Reason: Invalid license key format");
                }
                alvan_lic::LicenseError::InvalidData(msg) => {
                    println!("   📊 Reason: Invalid data - {}", msg);
                }
                alvan_lic::LicenseError::Base64Error(_) => {
                    println!("   🔤 Reason: Base64 decoding error");
                }
                alvan_lic::LicenseError::ChronoError(_) => {
                    println!("   📅 Reason: Time parsing error");
                }
            }
        }
    }
}

fn get_secret_key() -> String {
    println!("\n🔐 Secret Key Configuration");
    println!("1. Use default secret key (recommended for testing)");
    println!("2. Enter custom secret key");
    print!("Choose option (1-2): ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    match input.trim() {
        "1" => {
            println!("✅ Using default secret key");
            get_default_secret()
        }
        "2" => {
            print!("Enter your secret key: ");
            io::stdout().flush().unwrap();
            let mut secret = String::new();
            io::stdin().read_line(&mut secret).unwrap();
            let secret = secret.trim().to_string();
            
            if secret.is_empty() {
                println!("⚠️  Empty secret key provided, using default instead");
                get_default_secret()
            } else if secret.len() < 8 {
                println!("⚠️  Secret key is very short (less than 8 characters). Consider using a longer key for better security.");
                secret
            } else {
                println!("✅ Using custom secret key");
                secret
            }
        }
        _ => {
            println!("❌ Invalid choice, using default secret key");
            get_default_secret()
        }
    }
}

fn get_hours_input() -> u64 {
    loop {
        println!("\n⏰ License Duration Options:");
        println!("1. 1 hour");
        println!("2. 24 hours (1 day)");
        println!("3. 168 hours (1 week)");
        println!("4. 720 hours (30 days)");
        println!("5. 8760 hours (1 year)");
        println!("6. Custom duration");
        print!("Choose duration (1-6): ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => return 1,
            "2" => return 24,
            "3" => return 168,
            "4" => return 720,
            "5" => return 8760,
            "6" => {
                print!("Enter custom duration in hours: ");
                io::stdout().flush().unwrap();
                let mut custom_input = String::new();
                io::stdin().read_line(&mut custom_input).unwrap();
                
                match custom_input.trim().parse::<u64>() {
                    Ok(hours) if hours > 0 => return hours,
                    Ok(_) => println!("❌ Duration must be greater than 0"),
                    Err(_) => println!("❌ Invalid number format"),
                }
            }
            _ => println!("❌ Invalid choice. Please enter 1-6."),
        }
    }
}

fn get_default_secret() -> String {
    "alvan-default-secret-key-2024".to_string()
}
