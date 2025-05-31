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

Or install the CLI tool directly:

```bash
cargo install alvan-lic
```

Then run the interactive CLI:

```bash
alvan-cli
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
