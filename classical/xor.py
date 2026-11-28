
# XOR two pieces of data using a key
def xor_bytes(data, key):

    # Check that the input is bytes
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    # Check that the key is bytes
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    # The key cannot be empty
    if len(key) == 0:
        raise ValueError("Key cannot be empty")

    # Store the result
    result = []

    # Process each byte
    for index in range(len(data)):

        # Get the current data byte
        data_byte = data[index]

        # Get the matching key byte
        key_byte = key[index % len(key)]

        # Perform XOR operation
        result_byte = data_byte ^ key_byte

        # Save the result
        result.append(result_byte)

    # Convert the result into bytes
    return bytes(result)


# Encrypt data using XOR
def xor_encrypt(plaintext, key):

    return xor_bytes(plaintext, key)


# Decrypt data using XOR
def xor_decrypt(ciphertext, key):

    return xor_bytes(ciphertext, key)
