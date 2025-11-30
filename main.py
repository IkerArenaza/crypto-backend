from fastapi import FastAPI, HTTPException

import crypto_service as cs
from schemas import (
    Sha256Request,
    HashResponse,
    Argon2Request,
    AesEncryptRequest,
    AesEncryptResponse,
    AesDecryptRequest,
    AesDecryptResponse,
    ChaChaEncryptRequest,
    ChaChaEncryptResponse,
    ChaChaDecryptRequest,
    ChaChaDecryptResponse,
    RsaEncryptRequest,
    RsaEncryptResponse,
    RsaDecryptRequest,
    RsaDecryptResponse,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)

app = FastAPI(title="Crypto Backend Project")


@app.get("/")
def read_root():
    return {"message": "Crypto backend OK"}


# ---------- Hashes ----------

@app.post("/api/hash/sha256", response_model=HashResponse)
def hash_sha256(body: Sha256Request):
    result = cs.sha256_hash(body.text)
    return HashResponse(hash=result)


@app.post("/api/hash/argon2", response_model=HashResponse)
def hash_argon2(body: Argon2Request):
    result = cs.argon2_hash(body.password)
    return HashResponse(hash=result)


# ---------- AES-256-CBC ----------

@app.post("/api/encrypt/aes_cbc", response_model=AesEncryptResponse)
def encrypt_aes(body: AesEncryptRequest):
    try:
        ciphertext_b64 = cs.encrypt_aes_cbc(body.plaintext, body.key_b64, body.iv_b64)
        return AesEncryptResponse(ciphertext_b64=ciphertext_b64)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/decrypt/aes_cbc", response_model=AesDecryptResponse)
def decrypt_aes(body: AesDecryptRequest):
    try:
        plaintext = cs.decrypt_aes_cbc(body.ciphertext_b64, body.key_b64, body.iv_b64)
        return AesDecryptResponse(plaintext=plaintext)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- ChaCha20 ----------

@app.post("/api/encrypt/chacha20", response_model=ChaChaEncryptResponse)
def encrypt_chacha(body: ChaChaEncryptRequest):
    try:
        ciphertext_b64 = cs.encrypt_chacha20(
            body.plaintext, body.key_b64, body.nonce_b64
        )
        return ChaChaEncryptResponse(ciphertext_b64=ciphertext_b64)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/decrypt/chacha20", response_model=ChaChaDecryptResponse)
def decrypt_chacha(body: ChaChaDecryptRequest):
    try:
        plaintext = cs.decrypt_chacha20(
            body.ciphertext_b64, body.key_b64, body.nonce_b64
        )
        return ChaChaDecryptResponse(plaintext=plaintext)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- RSA-OAEP ----------

@app.post("/api/encrypt/rsa", response_model=RsaEncryptResponse)
def encrypt_rsa(body: RsaEncryptRequest):
    ciphertext_b64 = cs.encrypt_rsa_oaep(body.plaintext)
    return RsaEncryptResponse(ciphertext_b64=ciphertext_b64)


@app.post("/api/decrypt/rsa", response_model=RsaDecryptResponse)
def decrypt_rsa(body: RsaDecryptRequest):
    plaintext = cs.decrypt_rsa_oaep(body.ciphertext_b64)
    return RsaDecryptResponse(plaintext=plaintext)


# ---------- Firma ECDSA (DSA/ECDSA) ----------

@app.post("/api/sign/dsa", response_model=SignResponse)
def sign_message(body: SignRequest):
    signature_b64 = cs.sign_ecdsa(body.message)
    return SignResponse(signature_b64=signature_b64)


@app.post("/api/verify/dsa", response_model=VerifyResponse)
def verify_message(body: VerifyRequest):
    valid = cs.verify_ecdsa(body.message, body.signature_b64)
    return VerifyResponse(valid=valid)