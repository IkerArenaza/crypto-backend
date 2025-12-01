Crypto Backend — Proyecto Final (Lenguajes de Programación)

Este proyecto implementa un backend criptográfico completo utilizando FastAPI, cumpliendo con todos los requisitos del proyecto final de la asignatura Lenguajes de Programación.

Incluye:

Hashing seguro (SHA-256 y Argon2)

Cifrado simétrico (AES-256-CBC y ChaCha20)

Cifrado asimétrico (RSA-OAEP)

Firma y verificación digital (DSA/ECDSA)

Serialización Base64 para claves, IV/Nonce y ciphertext

Estructura modular: main.py, crypto_service.py, schemas.py

Endpoints separados para cifrado/descifrado y firma/verificación

Entradas y salidas en JSON

Tecnologías utilizadas

Python 3

FastAPI

Uvicorn

cryptography

argon2-cffi

Estructura del proyecto
crypto-backend/
│
├── main.py
├── crypto_service.py
├── schemas.py
├── requirements.txt
└── README.md

Instalación y Ejecución
1 Crear entorno virtual
python -m venv venv

Activar entorno:

Windows

venv\Scripts\activate


Linux / Mac

source venv/bin/activate

2 Instalar dependencias
pip install -r requirements.txt

3 Ejecutar el servidor
uvicorn main:app --reload


Abrir en el navegador:

http://127.0.0.1:8000/docs

Aquí se encuentra la documentación automática generada por Swagger.

Problema común en Windows (Microsoft Store):
"uvicorn" no se reconoce" o No module named uvicorn

Si Python se instaló desde Microsoft Store, es muy común que pip install -r requirements.txt instale los paquetes fuera del venv, provocando que FastAPI o Uvicorn no funcionen.

Esto genera errores como:

C:\...\venv\Scripts\python.exe: No module named uvicorn

Solución oficial (garantizada)

Activar el entorno virtual:

venv\Scripts\activate


Instalar los paquetes dentro del venv usando su propio ejecutable:

venv\Scripts\python.exe -m pip install uvicorn[standard] fastapi cryptography argon2-cffi


Ejecutar el proyecto usando el python del venv:

venv\Scripts\python.exe -m uvicorn main:app --reload


Abrir en el navegador:

http://127.0.0.1:8000/docs

Cómo verificar que funcionó
venv\Scripts\python.exe -m pip list


Debe mostrar uvicorn, fastapi, cryptography y argon2-cffi dentro del entorno.

Endpoints Implementados (10/10)
Tipo	Algoritmo	Operación	Endpoint
Hash	SHA-256	Generar hash	POST /api/hash/sha256
Hash	Argon2	Hash contraseña	POST /api/hash/argon2
Simétrico	AES-256-CBC	Cifrar	POST /api/encrypt/aes_cbc
Simétrico	AES-256-CBC	Descifrar	POST /api/decrypt/aes_cbc
Simétrico	ChaCha20	Cifrar	POST /api/encrypt/chacha20
Simétrico	ChaCha20	Descifrar	POST /api/decrypt/chacha20
Asimétrico	RSA-OAEP	Cifrar	POST /api/encrypt/rsa
Asimétrico	RSA-OAEP	Descifrar	POST /api/decrypt/rsa
Firma	DSA/ECDSA	Firmar	POST /api/sign/dsa
Firma	DSA/ECDSA	Verificar	POST /api/verify/dsa
Ejemplos de uso

Todos los endpoints se pueden probar desde Swagger o Postman.

SHA-256
POST /api/hash/sha256
{
  "text": "hola"
}

Argon2
POST /api/hash/argon2
{
  "password": "MiPassword123"
}

Claves de prueba (AES y ChaCha20)

Estas claves funcionan para pruebas rápidas:

AES key_b64:     lgn8WcKA12J7ulkKQSU8sR0JpTfM2SJpqObisuQrjwU=
AES iv_b64:      5/z92mAzGT2HMrS0rNUVbg==

ChaCha20 key:    lgn8WcKA12J7ulkKQSU8sR0JpTfM2SJpqObisuQrjwU=
ChaCha20 nonce:  eMyvQhD2+/UWhO2asibcww==

Explicación de seguridad
SHA-256

Seguro para integridad, no adecuado para contraseñas.

Argon2

La mejor opción para contraseñas: lento, resistente a GPUs/ASICs.

AES-256-CBC

Estándar mundial, muchísimo más seguro que DES (roto).

ChaCha20

Seguro, moderno y rápido. Excelente en software sin AES-HW.

RSA-OAEP

Versión segura de RSA. OAEP evita ataques clásicos al cifrado.

DSA/ECDSA

Firmas digitales eficientes, muy seguras y ampliamente usadas.

Documentación automática

http://127.0.0.1:8000/docs
