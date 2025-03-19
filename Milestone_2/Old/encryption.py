
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    key_id = data.get('key_id')
    plaintext = data.get('plaintext')
    algorithm = data.get('algorithm')

    if key_id not in keys:
        return jsonify({"error": "Key not found"}), 404

    key = base64.b64decode(keys[key_id])

    if algorithm == "AES":
        # Generate a random initialization vector (IV)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        ciphertext = base64.b64encode(iv + ciphertext).decode('utf-8')
    else:
        return jsonify({"error": "Unsupported algorithm"}), 400

    return jsonify({"ciphertext": ciphertext})