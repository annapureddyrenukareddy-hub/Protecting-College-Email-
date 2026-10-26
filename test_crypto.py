
import json

from crypto_utils import (
    create_secure_email,
    receive_secure_email,
)


print("Testing Protecting College E-Mail")
print("-" * 40)

# Test 1: Send and receive a message
email = create_secure_email(
    "Hello Student! Your assignment is attached."
)

print("Encrypted email created successfully.")

received = receive_secure_email(email)

assert received["message"] == (
    "Hello Student! Your assignment is attached."
)

print("PASS: Message decrypted successfully.")
print("PASS: Digital signature verified.")
print("Received message:", received["message"])

# Test 2: Detect tampering
tampered_email = dict(email)
tampered_email["ciphertext"] = (
    email["ciphertext"][:-4] + "AAAA"
)

try:
    receive_secure_email(tampered_email)
    raise AssertionError("Tampering was not detected!")
except (ValueError, Exception) as error:
    if isinstance(error, AssertionError):
        raise
    print("PASS: Modified email was rejected.")

print("-" * 40)
print("All basic security tests completed.")
