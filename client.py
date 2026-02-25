''' IMPORTS '''
import socket
import encryption_util as crypto
import threading
import json
import base64

# Network configuration
HOST = '127.0.0.1'
PORT = 65431

# AES256 Key
AES_KEY = None

# Send messages
# Takes in a socket, and OQS Signature (sk)
def send_message(socket, signing_algorithm):

    # Loop forever
    while True:
        message = input(">") # Get input
        signature = crypto.sign_message(message, signing_algorithm) # Create message signature
        ciphertext = crypto.aes_encrypt(AES_KEY, message.encode()) # Creates ciphertext from message

        # Create dictionary of ciphertext and signature
        data = {
            'message': base64.b64encode(ciphertext).decode(),
            'signature': base64.b64encode(signature).decode()
        }

        # Convert to serialized JSON object
        packet = json.dumps(data)
        
        # Send packet
        socket.sendall(packet.encode())

# Receive messages
# Takes in a socket, OQS Signature (sk), and partner's public signing key
def receive_message(socket, signing_algorithm, signing_key):
    
    # Loop forever
    while True:
        
        packet = socket.recv(4096).decode() # Receive packet from client
        data = json.loads(packet) # extract data from JSON object
        ciphertext = base64.b64decode(data['message']) # extract the ciphertext
        signature = base64.b64decode(data['signature']) # extract the signature
        message = crypto.aes_decrypt(AES_KEY, ciphertext) # decrypt the ciphertext

        # Verify signature
        if crypto.verify_signature(message, signing_algorithm, signature, signing_key):
            print("Sender: ", message.decode())
            print(">", end='', flush=True)

# Client setup
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # init TCP connection
    client_socket.connect((HOST, PORT))  # Connect to the server

    kem_algorithm = crypto.initialize_kem()  # Initialize post-quantum KEM
    public_kem = kem_algorithm.generate_keypair() # Generate keys, only need public

    sign_algorithm = crypto.initialize_sign() # Initialize PQ Signature
    public_sign = sign_algorithm.generate_keypair() # Generate keys, only need public


    ##### KEY EXCHANGE #####

    # Receive server keys
    data = client_socket.recv(4096).decode()  # Receive client's public key
    message = json.loads(data) # get data from JSON string
    server_public_kem = base64.b64decode(message['kem_pk']) # Get server KEM public key
    server_public_sign = base64.b64decode(message['sign_pk']) # Get server Signature public key

    # Package client public keys in dictionary
    data = {
    'kem_pk': base64.b64encode(public_kem).decode(),
    'sign_pk': base64.b64encode(public_sign).decode()
    }
    # Convert to JSON string
    message = json.dumps(data)

    # Send package of public keys to server
    client_socket.sendall(message.encode())
    
    # Receive the ciphertext and compute the shared secret
    shared_secret = client_socket.recv(4096)
    secret = kem_algorithm.decap_secret(shared_secret)

    # Use the shared secret as the AES key
    global AES_KEY
    AES_KEY = secret  # Use first 256 bits for AES key
    
    ##### SENDING & RECEIVING THREADS #####
    sending_message_thread = threading.Thread(target=send_message, args=(client_socket, sign_algorithm, ))
    receive_message_thread = threading.Thread(target=receive_message, args=(client_socket, sign_algorithm, server_public_sign, ))
    sending_message_thread.start()
    receive_message_thread.start()

# Main
if __name__ == "__main__":
    start_client()