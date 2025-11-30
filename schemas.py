from pydantic import BaseModel


# ----- Hashing -----

class Sha256Request(BaseModel):
    text: str


class HashResponse(BaseModel):
    hash: str


class Argon2Request(BaseModel):
    password: str


# ----- AES-256-CBC -----

class AesEncryptRequest(BaseModel):
    plaintext: str
    key_b64: str
    iv_b64: str


class AesEncryptResponse(BaseModel):
    ciphertext_b64: str


class AesDecryptRequest(BaseModel):
    ciphertext_b64: str
    key_b64: str
    iv_b64: str


class AesDecryptResponse(BaseModel):
    plaintext: str


# ----- ChaCha20 -----

class ChaChaEncryptRequest(BaseModel):
    plaintext: str
    key_b64: str
    nonce_b64: str


class ChaChaEncryptResponse(BaseModel):
    ciphertext_b64: str


class ChaChaDecryptRequest(BaseModel):
    ciphertext_b64: str
    key_b64: str
    nonce_b64: str


class ChaChaDecryptResponse(BaseModel):
    plaintext: str


# ----- RSA-OAEP -----

class RsaEncryptRequest(BaseModel):
    plaintext: str


class RsaEncryptResponse(BaseModel):
    ciphertext_b64: str


class RsaDecryptRequest(BaseModel):
    ciphertext_b64: str


class RsaDecryptResponse(BaseModel):
    plaintext: str


# ----- ECDSA (firma) -----

class SignRequest(BaseModel):
    message: str


class SignResponse(BaseModel):
    signature_b64: str


class VerifyRequest(BaseModel):
    message: str
    signature_b64: str


class VerifyResponse(BaseModel):
    valid: bool