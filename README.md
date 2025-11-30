🔐 Crypto Backend — Proyecto Final (Lenguajes de Programación)



Este proyecto implementa un backend criptográfico completo utilizando FastAPI, cumpliendo con los requisitos del proyecto final de la asignatura “Lenguajes de Programación”.



Incluye:



Hashing seguro (SHA-256 y Argon2)



Cifrado simétrico (AES-256-CBC y ChaCha20)



Cifrado asimétrico (RSA-OAEP)



Firma y verificación digital (ECDSA / DSA)



Endpoints separados para cifrado/descifrado y firma/verificación



Uso de Base64 en claves, IV/Nonce y datos cifrados



Comunicación 100% en formato JSON



Código separado en módulos (main.py, crypto\_service.py, schemas.py)



🚀 Tecnologías utilizadas



Python 3



FastAPI



Uvicorn



cryptography



argon2-cffi



📂 Estructura del proyecto

crypto-backend/

│

├── main.py

├── crypto\_service.py

├── schemas.py

├── requirements.txt

└── README.md



⚙️ Instalación y ejecución

1️⃣ Crear entorno virtual

python -m venv venv





Activar:



Windows

venv\\Scripts\\activate



Linux / Mac

source venv/bin/activate



2️⃣ Instalar dependencias

pip install -r requirements.txt



3️⃣ Ejecutar el servidor

uvicorn main:app --reload





Abrir en el navegador:



👉 http://127.0.0.1:8000/docs



Aquí se encuentra la documentación automática generada por Swagger.



🔐 Endpoints implementados (10/10)

Tipo	Algoritmo	Operación	Endpoint

Hash	SHA-256	Generar hash	POST /api/hash/sha256

Hash	Argon2	Hash de contraseña	POST /api/hash/argon2

Simétrico	AES-256-CBC	Cifrar	POST /api/encrypt/aes\_cbc

Simétrico	AES-256-CBC	Descifrar	POST /api/decrypt/aes\_cbc

Simétrico	ChaCha20	Cifrar	POST /api/encrypt/chacha20

Simétrico	ChaCha20	Descifrar	POST /api/decrypt/chacha20

Asimétrico	RSA-OAEP	Cifrar	POST /api/encrypt/rsa

Asimétrico	RSA-OAEP	Descifrar	POST /api/decrypt/rsa

Firma	ECDSA / DSA	Firmar mensaje	POST /api/sign/dsa

Firma	ECDSA / DSA	Verificar firma	POST /api/verify/dsa

🧪 Ejemplos de uso



Todos se pueden probar desde Swagger o Postman.



🔹 SHA-256



POST /api/hash/sha256



Request:



{

&nbsp; "text": "hola"

}





Response:



{

&nbsp; "hash": "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cdd4db79"

}



🔹 Argon2 (hash seguro)



POST /api/hash/argon2



{

&nbsp; "password": "MiPassword123"

}





Respuesta típica:



{

&nbsp; "hash": "$argon2id$v=19$m=65536,t=3,p=4$..."

}



🔑 Claves de prueba (AES y ChaCha20)



Úsalas en pruebas rápidas:



AES key\_b64: lgn8WcKA12J7ulkKQSU8sR0JpTfM2SJpqObisuQrjwU=

AES iv\_b64:  5/z92mAzGT2HMrS0rNUVbg==



ChaCha20 key\_b64:   lgn8WcKA12J7ulkKQSU8sR0JpTfM2SJpqObisuQrjwU=

ChaCha20 nonce\_b64: eMyvQhD2+/UWhO2asibcww==



🔹 AES — Cifrar

POST /api/encrypt/aes\_cbc





Body:



{

&nbsp; "plaintext": "mensaje secreto",

&nbsp; "key\_b64": "lgn8WcKA12J7ulkKQSU8sR0JpTfM2SJpqObisuQrjwU=",

&nbsp; "iv\_b64": "5/z92mAzGT2HMrS0rNUVbg=="

}



🔹 AES — Descifrar

{

&nbsp; "ciphertext\_b64": "<resultado\_del\_cifrado>",

&nbsp; "key\_b64": "lgn8WcKA12J7ulkKQSU8sR0JpTfM2SJpqObisuQrjwU=",

&nbsp; "iv\_b64": "5/z92mAzGT2HMrS0rNUVbg=="

}



🔹 ChaCha20 — Cifrar

{

&nbsp; "plaintext": "secreto",

&nbsp; "key\_b64": "lgn8WcKA12J7ulkKQSU8sR0JpTfM2SJpqObisuQrjwU=",

&nbsp; "nonce\_b64": "eMyvQhD2+/UWhO2asibcww=="

}



🔹 RSA — Cifrar y descifrar



Cifrar:



{

&nbsp; "plaintext": "Mensaje secreto RSA"

}





Descifrar:



{

&nbsp; "ciphertext\_b64": "<ciphertext\_generado>"

}



🔹 Firma digital — ECDSA



Firmar:



{

&nbsp; "message": "Mensaje importante"

}





Verificar:



{

&nbsp; "message": "Mensaje importante",

&nbsp; "signature\_b64": "<firma\_generada>"

}



🛡️ Explicación de seguridad

🔸 SHA-256



Seguro para integridad, NO para contraseñas (demasiado rápido → vulnerable a brute-force).



🔸 Argon2



Optimizado para contraseñas: resistente a fuerza bruta, GPUs y ASICs.



🔸 AES-256-CBC



Estándar mundial de cifrado. Mucho más seguro que DES (56 bits → roto).



🔸 ChaCha20



Rápido, moderno, seguro. Ideal en software sin aceleración AES.



🔸 RSA-OAEP



Cifrado asimétrico seguro. OAEP evita ataques clásicos a RSA.



🔸 ECDSA



Firmas digitales seguras, eficientes y modernas.





Documentación automática:



👉 http://127.0.0.1:8000/docs

