import hashlib

@app.route('/generate-hash', methods=['POST'])
def generate_hash():
    data = request.json
    input_data = data.get('data')
    algorithm = data.get('algorithm')

    if algorithm == "SHA-256":
        hash_object = hashlib.sha256(input_data.encode())
    elif algorithm == "SHA-512":
        hash_object = hashlib.sha512(input_data.encode())
    else:
        return jsonify({"error": "Unsupported hashing algorithm"}), 400

    hash_value = base64.b64encode(hash_object.digest()).decode('utf-8')
    return jsonify({"hash_value": hash_value, "algorithm": algorithm})