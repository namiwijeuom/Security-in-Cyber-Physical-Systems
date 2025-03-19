from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import uuid
import os

app = Flask(__name__)

# In-memory storage for keys (for demonstration purposes)
keys = {}

@app.route('/generate-key', methods=['POST'])
def generate_key():
    data = request.json
    key_type = data.get('key_type')
    key_size = data.get('key_size')

    if key_type == "AES":
        # Generate a symmetric key (AES)
        key = base64.b64encode(os.urandom(key_size // 8)).decode('utf-8')
    elif key_type == "RSA":
        # Generate an RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        key = base64.b64encode(private_key_bytes).decode('utf-8')
    else:
        return jsonify({"error": "Unsupported key type"}), 400

    key_id = str(uuid.uuid4())
    keys[key_id] = key

    return jsonify({"key_id": key_id, "key_value": key})

if __name__ == '__main__':
    app.run(debug=True)