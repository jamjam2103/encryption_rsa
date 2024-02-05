from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def encrypt_rsa(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.urlsafe_b64encode(ciphertext).decode()

def decrypt_rsa(ciphertext, private_key):
    decrypted_message = private_key.decrypt(
        base64.urlsafe_b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# Example usage:
message_to_encrypt = "Hello, this is a secret message!"

# Generate RSA key pair
private_key, public_key = generate_key_pair()

# Encrypt the message using RSA public key
encrypted_message = encrypt_rsa(message_to_encrypt, public_key)
print("Encrypted Message:", encrypted_message)

# Decrypt the message using RSA private key
decrypted_message = decrypt_rsa(encrypted_message, private_key)
print("Decrypted Message:", decrypted_message)
