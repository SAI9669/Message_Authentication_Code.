# Secure HMAC Implementation

This project provides a Secure HMAC (Hash-based Message Authentication Code) Implementation using Python. It enhances security with key strengthening (PBKDF2), random nonces (salt), and constant-time comparison to prevent timing attacks.

## Features
- PBKDF2 Key Derivation for added security
- Random Nonce (Salt) for Each MAC to prevent replay attacks
- Base64 Encoding for Safe Transmission
- Constant-Time MAC Verification to avoid timing attacks
- Tamper Detection – Ensures message integrity

## Installation
No external dependencies are required. The script runs with Python 3.x.

## Usage
### Basic MAC Generation and Verification
message = "Hello, this is a secure message."
key = "supersecretkey"

hmac_instance = SecureHMAC(key)
mac = hmac_instance.generate_mac(message)
Generated MAC: mac

if hmac_instance.verify_mac(message, mac):
    MAC Verified: Message is authentic
else:
    MAC Verification Failed

### Tampered Message Detection
tampered_message = "Hello, this is a hacked message."
if hmac_instance.verify_mac(tampered_message, mac):
    MAC Verified (Tampered) – This should NOT happen!
else:
    MAC Verification Failed – Tampering Detected!

### Replay Attack Prevention
new_mac = hmac_instance.generate_mac(message)
if mac == new_mac:
    Replay Attack Detected – Same MAC for different requests!
else:
    Different MACs Generated – Replay Attack Prevented!

## Security Considerations
- Unique MAC per Message: Random nonce ensures a new MAC for each message.
- PBKDF2 Key Derivation: Strengthens security against brute-force attacks.
- HMAC-SHA256: Uses strong cryptographic hashing.


