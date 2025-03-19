@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    key_id = data.get('key_id')
    ciphertext = data.get('ciphertext')
    algorithm = data.get('algorithm')

    if key_id not in keys:
        return jsonify({"error": "Key not found"}), 404

    key = base64.b64decode(keys[key_id])
    ciphertext = base64.b64decode(ciphertext)

    if algorithm == "AES":
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = plaintext.decode('utf-8')
    else:
        return jsonify({"error": "Unsupported algorithm"}), 400

    return jsonify({"plaintext": plaintext})