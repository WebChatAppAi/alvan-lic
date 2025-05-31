//! Simple license key generator

use alvan_lic::LicenseGenerator;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 3 {
        println!("Usage: {} <secret_key> <hours>", args[0]);
        println!("Example: {} my-secret-key 24", args[0]);
        std::process::exit(1);
    }
    
    let secret = &args[1];
    let hours: u64 = match args[2].parse() {
        Ok(h) => h,
        Err(_) => {
            println!("Error: Invalid number of hours '{}'", args[2]);
            std::process::exit(1);
        }
    };
    
    let generator = LicenseGenerator::new(secret);
    
    match generator.generate_key(hours) {
        Ok(license_key) => {
            println!("{}", license_key);
        }
        Err(e) => {
            eprintln!("Error generating license: {}", e);
            std::process::exit(1);
        }
    }
}
