@app.route('/verify-hash', methods=['POST'])
def verify_hash():
    data = request.json
    input_data = data.get('data')
    hash_value = data.get('hash_value')
    algorithm = data.get('algorithm')

    if algorithm == "SHA-256":
        hash_object = hashlib.sha256(input_data.encode())
    elif algorithm == "SHA-512":
        hash_object = hashlib.sha512(input_data.encode())
    else:
        return jsonify({"error": "Unsupported hashing algorithm"}), 400

    computed_hash = base64.b64encode(hash_object.digest()).decode('utf-8')
    is_valid = computed_hash == hash_value

    if is_valid:
        message = "Hash matches the data."
    else:
        message = "Hash does not match the data."

    return jsonify({"is_valid": is_valid, "message": message})