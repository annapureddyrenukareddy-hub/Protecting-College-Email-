import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from key_manager import load_private_key, load_public_key, setup_keys


def encode_bytes(data):
    """Convert bytes into text that JSON can store."""
    return base64.b64encode(data).decode("utf-8")


def decode_bytes(data):
    """Convert Base64 text back into bytes."""
    return base64.b64decode(data, validate=True)


def create_secure_email(message, attachment_name=None, attachment_data=None,
                        recipient_urn="", recipient_public_key=None):
    """Sign a payload, encrypt it with AES-GCM, and wrap the AES key for its student."""
    setup_keys()
    recipient_urn = str(recipient_urn or "").strip().upper()
    payload = {
        "sender": "Faculty",
        "recipient": "Student",
        "recipient_urn": recipient_urn,
        "message": message,
        "attachment_name": attachment_name,
        "attachment_data": encode_bytes(attachment_data) if attachment_data is not None else None,
    }
    plaintext = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

    faculty_private_key = load_private_key("faculty")
    signature = faculty_private_key.sign(
        plaintext,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    signed_content = json.dumps({
        "payload": encode_bytes(plaintext),
        "signature": encode_bytes(signature),
    }).encode("utf-8")
    encrypted_content = AESGCM(aes_key).encrypt(nonce, signed_content, None)

    if recipient_public_key is None:
        recipient_public_key = load_public_key("student")
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "sender": "Faculty",
        "recipient": "Student",
        "recipient_urn": recipient_urn,
        "algorithm": "AES-256-GCM + RSA-OAEP-SHA256 + RSA-PSS-SHA256",
        "nonce": encode_bytes(nonce),
        "encrypted_key": encode_bytes(encrypted_aes_key),
        "ciphertext": encode_bytes(encrypted_content),
    }


def receive_secure_email(envelope, student_private_key=None, expected_urn=None):
    """Check the account URN, decrypt, and verify the faculty signature."""
    envelope_urn = str(envelope.get("recipient_urn", "")).strip().upper()
    expected_urn_key = str(expected_urn or "").strip().upper()
    if expected_urn is not None and (not envelope_urn or envelope_urn != expected_urn_key):
        raise ValueError("Recipient URN does not match the logged-in account.")

    if student_private_key is None:
        student_private_key = load_private_key("student")
    aes_key = student_private_key.decrypt(
        decode_bytes(envelope["encrypted_key"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    signed_content = AESGCM(aes_key).decrypt(
        decode_bytes(envelope["nonce"]), decode_bytes(envelope["ciphertext"]), None,
    )
    signed_data = json.loads(signed_content.decode("utf-8"))
    plaintext = decode_bytes(signed_data["payload"])
    signature = decode_bytes(signed_data["signature"])
    faculty_public_key = load_public_key("faculty")
    faculty_public_key.verify(
        signature,
        plaintext,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    payload = json.loads(plaintext.decode("utf-8"))
    signed_urn = str(payload.get("recipient_urn", "")).strip().upper()
    if signed_urn != envelope_urn:
        raise ValueError("Signed recipient URN does not match envelope URN.")
    if expected_urn is not None and signed_urn != expected_urn_key:
        raise ValueError("Signed recipient URN does not match the logged-in account.")
    attachment_data = payload.get("attachment_data")
    if attachment_data is not None:
        payload["attachment_data"] = decode_bytes(attachment_data)
    return payload
