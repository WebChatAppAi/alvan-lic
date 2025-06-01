<div align="center">

# 🔐 alvan-lic

**A Rust crate for generating and validating time-based license keys with offline validation**

[![Crates.io](https://img.shields.io/crates/v/alvan-lic?style=for-the-badge)](https://crates.io/crates/alvan-lic)
[![Downloads](https://img.shields.io/crates/d/alvan-lic?style=for-the-badge)](https://crates.io/crates/alvan-lic)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=for-the-badge)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?style=for-the-badge)](https://www.rust-lang.org)

[📦 Crates.io](https://crates.io/crates/alvan-lic) | [📖 Documentation](https://docs.rs/alvan-lic) | [🐙 GitHub](https://github.com/WebChatAppAi/alvan-lic)

</div>

---

## ✨ Features

<table>
<tr>
<td>🔐</td>
<td><strong>Secure</strong></td>
<td>Uses HMAC-SHA256 for cryptographic signing</td>
</tr>
<tr>
<td>⏱️</td>
<td><strong>Time-based</strong></td>
<td>Create licenses valid for any duration (hours)</td>
</tr>
<tr>
<td>🔌</td>
<td><strong>Offline</strong></td>
<td>No internet connection required for validation</td>
</tr>
<tr>
<td>🚀</td>
<td><strong>Fast</strong></td>
<td>Minimal dependencies and efficient implementation</td>
</tr>
<tr>
<td>🛡️</td>
<td><strong>Tamper-proof</strong></td>
<td>Any modification to the license key will invalidate it</td>
</tr>
</table>

## 📦 Installation

### As a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
alvan-lic = "0.1.0"
```

### As a CLI Tool

Install the CLI tool directly from [crates.io](https://crates.io/crates/alvan-lic):

```bash
cargo install alvan-lic
```

Then run the interactive CLI:

```bash
alvan-cli
```

## 🚀 Quick Start

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
            println!("✅ Valid for {:.1} more hours", info.hours_remaining);
        }
        Err(e) => {
            println!("❌ Invalid license: {}", e);
        }
    }
}
```

## 📖 Usage

### 🔑 Generating License Keys

```rust
use alvan_lic::LicenseGenerator;

let generator = LicenseGenerator::new("secret-key");

// Generate different duration licenses
let one_hour = generator.generate_key(1).unwrap();        // 1 hour
let one_day = generator.generate_key(24).unwrap();        // 24 hours
let one_month = generator.generate_key(24 * 30).unwrap(); // 30 days
let one_year = generator.generate_key(24 * 365).unwrap(); // 365 days
```

### ✅ Validating License Keys

```rust
use alvan_lic::LicenseValidator;

let validator = LicenseValidator::new("secret-key");

match validator.validate_key(&license_key) {
    Ok(info) => {
        println!("✅ License is valid!");
        println!("📅 Issued: {}", info.issued_at);
        println!("⏰ Expires: {}", info.expires_at);
        println!("⏳ Hours remaining: {:.2}", info.hours_remaining);
    }
    Err(e) => {
        println!("❌ License validation failed: {}", e);
    }
}
```

## 🔒 Security Considerations

> **⚠️ Important Security Notes**

### 🔐 Secret Key Management
- **Use a strong, randomly generated secret key**
- **Keep your secret key secure and never expose it**
- **Use different secret keys for different applications**

### 🔌 Offline Validation
- The same secret key must be used for generation and validation
- Keys cannot be forged without knowing the secret key  
- Validation works completely offline

### ⏰ Time Synchronization
- Ensure system clocks are reasonably synchronized
- Keys are validated against the system's current time

## 📋 License Format

All license keys follow this format:

```
alvan-<base64-encoded-payload-and-signature>
```

**Example:**
```
alvan-MTcwNDQ2NzI4MjoxNzA0NTUzNjgyLkPCt8K3w4Qpw6ZVwq0N...
```

## ⚠️ Error Handling

The crate provides detailed error types for robust error handling:

| Error Type | Description |
|------------|-------------|
| `InvalidFormat` | The license key format is incorrect |
| `InvalidSignature` | The signature doesn't match (wrong secret key) |
| `Expired` | The license has expired |
| `InvalidData` | The license data is corrupted |

## 📚 Examples

Check out the `examples/` directory for more detailed usage examples:

- Basic license generation and validation
- CLI tool implementation  
- Advanced error handling patterns

## 🤝 Contributing

Contributions are welcome! We appreciate your help in making this crate better.

### How to Contribute
1. 🍴 Fork the repository
2. 🌿 Create a feature branch
3. 💻 Make your changes
4. ✅ Add tests for new functionality
5. 📝 Update documentation if needed
6. 🚀 Submit a Pull Request

## 📜 License

This project is dual-licensed under your choice of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or [opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or [apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))

---

<div align="center">

**[⭐ Star this repo](https://github.com/WebChatAppAi/alvan-lic) • [📦 View on crates.io](https://crates.io/crates/alvan-lic) • [🐛 Report Issues](https://github.com/WebChatAppAi/alvan-lic/issues)**

Made with ❤️ by [WebChatAppAi](https://github.com/WebChatAppAi)

</div>
