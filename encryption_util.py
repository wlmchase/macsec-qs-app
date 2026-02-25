''' IMPORTS '''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import oqs

### ENCRYPTION UTIL ###
''' helper file to deal with all things cryptography '''

# AES key size
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 16  # 128 bit nonce

# Initialize the PQ key exchange mechanism
def initialize_kem():
    return oqs.KeyEncapsulation("Kyber512")  # KEM algorithm (Kyber512)

# Initialize PQ Dilithium signing
def initialize_sign():
    return oqs.Signature("Dilithium2") # Signing algorithm (Dilithium)

# AES256 Encryption in CTR mode
def aes_encrypt(key, data):
    nonce = os.urandom(AES_NONCE_SIZE) # Generate a random nonce
    cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce + ciphertext  # Prepend nonce to ciphertext

# AES256 Decryption
def aes_decrypt(key, data):
    nonce = data[:AES_NONCE_SIZE] # retreive nonce
    ciphertext = data[AES_NONCE_SIZE:]
    cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Sign a message    
def sign_message(message, signing_algorithm):
    signature = signing_algorithm.sign(message.encode())
    return signature

# Verify message signature    
def verify_signature(message, signing_algorithm, signature, signing_key):
    return signing_algorithm.verify(message, signature, signing_key)