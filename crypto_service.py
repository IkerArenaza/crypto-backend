import base64
import hashlib

from argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

backend = default_backend()

# ---------- Utilidades Base64 ----------

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("utf-8"))


# ---------- Hashes ----------

def sha256_hash(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


_ph = PasswordHasher()  # Argon2


def argon2_hash(password: str) -> str:
    return _ph.hash(password)


def argon2_verify(password: str, hashed: str) -> bool:
    """
    Función de verificación pedida en la consigna.
    Se puede usar en tests o en otro endpoint si queréis.
    """
    try:
        return _ph.verify(hashed, password)
    except Exception:
        return False


# ---------- AES-256-CBC ----------

def encrypt_aes_cbc(plaintext: str, key_b64: str, iv_b64: str) -> str:
    key = b64decode(key_b64)
    iv = b64decode(iv_b64)

    if len(key) != 32:
        raise ValueError("La clave AES debe tener 32 bytes (256 bits).")
    if len(iv) != 16:
        raise ValueError("El IV para CBC debe tener 16 bytes.")

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return b64encode(ciphertext)


def decrypt_aes_cbc(ciphertext_b64: str, key_b64: str, iv_b64: str) -> str:
    key = b64decode(key_b64)
    iv = b64decode(iv_b64)
    ciphertext = b64decode(ciphertext_b64)

    if len(key) != 32:
        raise ValueError("La clave AES debe tener 32 bytes (256 bits).")
    if len(iv) != 16:
        raise ValueError("El IV para CBC debe tener 16 bytes.")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode("utf-8")


# ---------- ChaCha20 ----------

def encrypt_chacha20(plaintext: str, key_b64: str, nonce_b64: str) -> str:
    key = b64decode(key_b64)
    nonce = b64decode(nonce_b64)

    if len(key) != 32:
        raise ValueError("La clave ChaCha20 debe tener 32 bytes.")
    if len(nonce) != 16:
        raise ValueError("El nonce ChaCha20 debe tener 16 bytes.")

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()

    return b64encode(ciphertext)


def decrypt_chacha20(ciphertext_b64: str, key_b64: str, nonce_b64: str) -> str:
    key = b64decode(key_b64)
    nonce = b64decode(nonce_b64)
    ciphertext = b64decode(ciphertext_b64)

    if len(key) != 32:
        raise ValueError("La clave ChaCha20 debe tener 32 bytes.")
    if len(nonce) != 16:
        raise ValueError("El nonce ChaCha20 debe tener 16 bytes.")

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode("utf-8")


# ---------- Claves asimétricas: RSA y ECDSA ----------

# RSA 2048 bits para cifrado OAEP
_RSA_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=backend,
)
_RSA_PUBLIC_KEY = _RSA_PRIVATE_KEY.public_key()

# ECDSA (equivalente moderno a DSA/ECDSA) para firma
_EC_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1(), backend)
_EC_PUBLIC_KEY = _EC_PRIVATE_KEY.public_key()


def encrypt_rsa_oaep(plaintext: str) -> str:
    ciphertext = _RSA_PUBLIC_KEY.encrypt(
        plaintext.encode("utf-8"),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64encode(ciphertext)


def decrypt_rsa_oaep(ciphertext_b64: str) -> str:
    ciphertext = b64decode(ciphertext_b64)
    plaintext = _RSA_PRIVATE_KEY.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


def sign_ecdsa(message: str) -> str:
    signature = _EC_PRIVATE_KEY.sign(
        message.encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    return b64encode(signature)


def verify_ecdsa(message: str, signature_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature

    signature = b64decode(signature_b64)
    try:
        _EC_PUBLIC_KEY.verify(
            signature,
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False