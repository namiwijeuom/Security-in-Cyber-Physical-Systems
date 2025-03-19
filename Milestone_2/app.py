from fastapi import FastAPI, HTTPException
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
from pydantic import BaseModel

app = FastAPI()

# In-memory storage for keys (for demonstration purposes)
keys_store = {}

# KeyGenerationRequest model
class KeyGenerationRequest(BaseModel):
    key_type: str
    key_size: int

# Update the endpoint to use the request body
@app.post("/generate-key")
async def generate_key(request: KeyGenerationRequest):
    key_type = request.key_type
    key_size = request.key_size

    if key_type not in ["AES", "RSA"]:
        raise HTTPException(status_code=400, detail="Unsupported key type")
    
    if key_type == "AES":
        if key_size not in [128, 192, 256]:
            raise HTTPException(status_code=400, detail="Invalid key size for AES")
        key = os.urandom(key_size // 8)  # Generate random bytes for AES key
    elif key_type == "RSA":
        if key_size not in [2048, 3072, 4096]:
            raise HTTPException(status_code=400, detail="Invalid key size for RSA")
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    
    # Store the key in memory
    key_id = str(len(keys_store) + 1)
    keys_store[key_id] = key
    
    # Serialize and encode the key in Base64
    if key_type == "AES":
        key_value = base64.b64encode(key).decode()
    elif key_type == "RSA":
        key_value = base64.b64encode(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode()
    
    return {"key_id": key_id, "key_value": key_value}

# EncryptionRequest model
class EncryptionRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str

# Update the endpoint to use the request body
@app.post("/encrypt")
async def encrypt(request: EncryptionRequest):
    key_id = request.key_id
    plaintext = request.plaintext
    algorithm = request.algorithm

    if key_id not in keys_store:
        raise HTTPException(status_code=404, detail="Key not found")
    
    key = keys_store[key_id]
    
    if algorithm == "AES":
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the plaintext to match block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt the data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        ciphertext = base64.b64encode(iv + ciphertext).decode()  # Include IV in the output
    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    
    return {"ciphertext": ciphertext}

# DecryptionRequest model
class DecryptionRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str

# Update the endpoint to use the request body
@app.post("/decrypt")
async def decrypt(request: DecryptionRequest):
    key_id = request.key_id
    ciphertext = request.ciphertext
    algorithm = request.algorithm

    if key_id not in keys_store:
        raise HTTPException(status_code=404, detail="Key not found")
    
    key = keys_store[key_id]
    
    if algorithm == "AES":
        # Decode the Base64 ciphertext and extract IV
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        plaintext = plaintext.decode()
    else:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")
    
    return {"plaintext": plaintext}

# HashGeneration model
class HashGeneration(BaseModel):
    data: str
    algorithm: str

# Hash Generation Endpoint
@app.post("/generate-hash")
async def generate_hash(request: HashGeneration):
    data = request.data
    algorithm = request.algorithm

    if algorithm not in ["SHA-256", "SHA-512"]:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")
    
    if algorithm == "SHA-256":
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif algorithm == "SHA-512":
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    
    digest.update(data.encode())
    hash_value = base64.b64encode(digest.finalize()).decode()
    
    return {"hash_value": hash_value, "algorithm": algorithm}

# HashVerification model
class HashVerification(BaseModel):
    data: str
    hash_value: str
    algorithm: str

# Hash Verification Endpoint
@app.post("/verify-hash")
async def verify_hash(request: HashVerification):
    data = request.data
    hash_value = request.hash_value
    algorithm = request.algorithm
    
    if algorithm not in ["SHA-256", "SHA-512"]:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")
    
    if algorithm == "SHA-256":
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif algorithm == "SHA-512":
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    
    digest.update(data.encode())
    computed_hash = base64.b64encode(digest.finalize()).decode()
    
    is_valid = computed_hash == hash_value
    message = "Hash matches the data." if is_valid else "Hash does not match the data."
    
    return {"is_valid": is_valid, "message": message}

# Run the API
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)