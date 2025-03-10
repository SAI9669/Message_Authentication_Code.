import hmac
import hashlib
import os
import base64

class SecureHMAC:
    def __init__(self, key: str, hash_function=hashlib.sha256, salt_length=16):
        self.hash_function = hash_function
        self.salt_length = salt_length  
        self.key = self.derive_key(key)

    def derive_key(self, key: str) -> bytes:
        salt = os.urandom(self.salt_length)  # Generate random salt
        return hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000)  

    def generate_mac(self, message: str, nonce: bytes = None) -> str:
        if nonce is None:
            nonce = os.urandom(self.salt_length)  
        mac = hmac.new(self.key, nonce + message.encode(), self.hash_function).digest()
        return base64.b64encode(nonce + mac).decode()  

    def verify_mac(self, message: str, received_mac: str) -> bool:
        try:
            decoded = base64.b64decode(received_mac)
            nonce, mac = decoded[:self.salt_length], decoded[self.salt_length:]
            computed_mac = hmac.new(self.key, nonce + message.encode(), self.hash_function).digest()
            return hmac.compare_digest(mac, computed_mac) 
        except Exception:
            return False  



# 🔹 **Example 1: Basic MAC Generation and Verification**
message1 = "Hello, this is a secure message."
key = "supersecretkey"

hmac_instance = SecureHMAC(key)
mac1 = hmac_instance.generate_mac(message1)
print("\n🔹 Example 1: Basic MAC")
print("Generated MAC:", mac1)

# Verification
if hmac_instance.verify_mac(message1, mac1):
    print("✅ MAC Verified: Message is authentic")
else:
    print("❌ MAC Verification Failed")

# 🔹 **Example 2: Tampered Message Detection**
tampered_message = "Hello, this is a hacked message."

print("\n🔹 Example 2: Tampered Message Detection")
if hmac_instance.verify_mac(tampered_message, mac1):
    print("❌ MAC Verified (Tampered) – This should NOT happen!")
else:
    print("✅ MAC Verification Failed – Tampering Detected!")

# 🔹 **Example 3: Replay Attack Prevention**
print("\n🔹 Example 3: Replay Attack Prevention")

# Generating a new MAC for the same message
mac2 = hmac_instance.generate_mac(message1)
print("New MAC:", mac2)

if mac1 == mac2:
    print("❌ Replay Attack Detected – Same MAC for different requests!")
else:
    print("✅ Different MACs Generated – Replay Attack Prevented!")

