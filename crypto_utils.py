import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()


def hash_transaction(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sign_data(data: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )
    signature = private_key.sign(
        data.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(data: str, signature: str, public_key_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
        public_key.verify(
            base64.b64decode(signature),
            data.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
