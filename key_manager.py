
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Locate the project folder and keys folder
BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"


def generate_key_pair(name):
    """Generate an RSA public/private key pair."""

    private_path = KEYS_DIR / f"{name}_private.pem"
    public_path = KEYS_DIR / f"{name}_public.pem"

    # Do not replace existing keys
    if private_path.exists() and public_path.exists():
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    public_key = private_key.public_key()

    # Save the private key
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    private_path.write_bytes(private_bytes)

    # Save the public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_path.write_bytes(public_bytes)


def setup_keys():
    """Create faculty and student keys."""

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    generate_key_pair("faculty")
    generate_key_pair("student")


def load_private_key(name):
    """Load a private key from the keys folder."""

    path = KEYS_DIR / f"{name}_private.pem"

    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=None
    )


def load_public_key(name):
    """Load a public key from the keys folder."""

    path = KEYS_DIR / f"{name}_public.pem"

    return serialization.load_pem_public_key(
        path.read_bytes()
    )
