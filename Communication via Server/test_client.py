''' IMPORTS '''
import socket
import os
import threading
import json
import base64
from oqs import KeyEncapsulation, Signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Network configuration
HOST = '127.0.0.1'
PORT = 65432

# Message Sending Thread
class Send_Thread(threading.Thread):
    
    # Initialization
    # Takes the client socket, and it's crypto manager
    def __init__(self, socket, crypto_manager):
        super().__init__() # init for threading
        self.socket = socket # client socket
        self.crypto_manager = crypto_manager # the crypto_manager

    # The main function
    def run(self):
        # Loop forever until user quits
        while True:
            
            try:
                message = input().strip() # Get the user's input, remove leading and trailing white space
                
                # EXIT CONDITION
                if message == '/quit':
                    self.send_json('command', message) # send message to server for proper handling
                    break
                
                # COMMANDS
                elif message.startswith('/'):
                    self.send_json('command', message)
                    
                # NOT IN ENCRYPTED CHAT
                elif not self.crypto_manager.shared_secret:
                    self.socket.sendall((message + '\n').encode())
                
                # IN ENCRYPTED CHAT
                else:
                    # Sign and encrypt the message
                    try:
                        signature = self.crypto_manager.sign_message(message) # Sign the message
                        encrypted_msg = self.crypto_manager.encrypt_message(message) # Encrypt the message
                        #print(f" Encrypted message structure: {encrypted_msg}")
                        self.send_json('chat', encrypted_msg, signature) # Send the message and signature
                    except Exception as e:
                        print(f" Error encrypting/signing message: {e}")
                        continue
                    
            except Exception as e:
                print(f"Error sending message: {e}")
                break
        
        # Close the socket
        print('\nQuitting...')
        self.socket.close()
        os._exit(0)
    
    # Message builder using JSON
    # Takes in a message type, the message contents, and optionally a signature for encrypted and signed messages    
    ''' 
    Packets are built like so:
    message = {
        msg_type: (the message type),
        content: (this can be an encrypted message, public keys, or messages for the server),
        signature: (the signature of a message)
    }
    
    message types include:
        system
        init
        command
        chat
    '''
    def send_json(self, msg_type, content, signature=None):
        try:
            # Build the message as dictionary
            message = {
                'type': msg_type,
                'content': content
            }
            
            # Case for signature
            if signature:
                message['signature'] = signature
            
            # Convert to JSON string
            data = json.dumps(message) + '\n'
            #print(f" Sending JSON: {data[:100]}...")
            self.socket.sendall(data.encode()) # Send the message
            
        except Exception as e:
            print(f" Error sending JSON: {e}")
            raise

# Message Receiving Thread
class Receive_Thread(threading.Thread):
    
    # Initialization
    # Takes the client socket, and crypto manager
    def __init__(self, socket, crypto_manager):
        super().__init__() # init for threading
        self.socket = socket # the socket
        self.crypto_manager = crypto_manager # the crypto_manager
        self.buffer = "" # Buffer for incoming data

    # Main function
    def run(self):
        
        # Loop forever
        while True:
            try:
                data = self.socket.recv(1024).decode() # receive incoming data
                if not data: # if there is no data, exit
                    break
                
                # add data to buffer
                self.buffer += data 
                
                # Loop over buffer until no new line character is reached
                while '\n' in self.buffer:
                    
                    # Read line by line
                    line, self.buffer = self.buffer.split('\n', 1)
                    
                    try:
                        msg_data = json.loads(line) # Recovers dictionary from JSON string
                        msg_type = msg_data.get('type', 'system') # Get the message type, if none default to system message type
                        #print(f"Received message type: {msg_type}")
                        
                        # MESSAGE TYPE CHECKS
                        match msg_type:
                            
                            case 'public_keys': # MESSAGE TYPE: PUBLIC KEYS
                                # Received partner's public keys
                                response = self.crypto_manager.handle_public_keys(msg_data['content']) # generate ciphertext from KEM
                                response_str = json.dumps(response) + '\n' # Convert ciphertext to JSON string
                                self.socket.sendall(response_str.encode()) # send message
                            
                            case 'key_share': # MESSAGE TYPE: KEY SHARE
                                # Process the shared encrypted key
                                self.crypto_manager.handle_key_share(msg_data['content'])
                            
                            case 'sign_key': # MESSAGE TYPE: SIGNATURE KEY
                                # Received partner's public signing key
                                self.crypto_manager.extract_sign_key(msg_data['content'])
                            
                            case 'chat': # MESSAGE TYPE: CHAT - Client is in a chat with partner
                                self.process_private_chat(msg_data)
                            
                            case 'close_chat': # MESSAGE TYPE:CHAT CLOSED
                                self.crypto_manager.reset()
                                
                            case _:
                                print(f"\n{msg_data['content']}")
                            
                    except Exception as e:
                        print(f"JSON error: {e}")
                        continue
                    
            except Exception as e:
                print(f"\nError receiving message: {e}")
                break
        
        # Lost connection
        # Close socket        
        print('\nLost connection to server.')
        self.socket.close()
        os._exit(0)

    # process message when in an ecrypted chat
    def process_private_chat(self, msg_data):
        content = msg_data['content'] # Recover message contents
        if self.crypto_manager.shared_secret: # Check client is in a chat
            try:
                #print(f"Decrypting content")
                #print(f"Received encrypted structure: {content}")
                decrypted_content = self.crypto_manager.decrypt_message(content)
                #print(f"Decrypted content: {decrypted_content}")
                
                # Format the decrypted message with sender's name
                formatted_message = f"{self.crypto_manager.partner_username}: {decrypted_content}"
                
                # Verify signature
                if 'signature' in msg_data:
                    #print(f"Verifying signature")
                    if self.crypto_manager.verify_signature(decrypted_content, msg_data['signature']):
                        print(f"\n{formatted_message}")
                    else:
                        print("\nMessage signature verification failed!")
                else:
                    print(f"\n{formatted_message}")
            except Exception as e:
                print(f"Error decrypting/verifying message: {e}")
                #print(f"Session key: {base64.b64encode(self.crypto_manager.session_key)}")
        else:
            print(f"\n{content}")
        
# Cryptography Manager class
# Handles all things cryptography
class CryptoManager:
    
    # Initialization
    def __init__(self):
        
        ### PQ KEM & SIGNING ALGORITHMS
        self.kem = KeyEncapsulation("Kyber512") # KEM Algorithm
        self.sig = Signature("Dilithium2") # Signature Algorithm
        
        ### PERSONAL KEYS ###
        self.shared_secret = None # AES key
        
        self.kem_public_key = None # KEM public key
        self.signature_public_key = None # Signature pk
        
        ### PARTNER INFO ###
        self.partner_username = None
        self.partner_signature_public_key = None # Partner's Signature pk
        
        self.initialize_keys() # generate public keys
    
    # Resets AES key, and partner info when chat is closed 
    def reset(self):
        self.shared_secret = None
        self.partner_username = None
        self.partner_signature_public_key = None
        
    # Initializes KEM and Signature keys    
    def initialize_keys(self):
        # Generate KEM keypair (secret is not needed)
        self.public_key = self.kem.generate_keypair()
        
        # Generate signature keypair (secret is not needed)
        self.signature_public_key = self.sig.generate_keypair()
    
    # handler for when message type is public keys
    # stores the partner's signing public key
    # generates the ciphertext and shared secret (AES key) from partner's public KEM key
    # returns dictionary payload with ciphertext to send to partner    
    def handle_public_keys(self, data):
        partner_kem_public_key = base64.b64decode(data['kem_public_key']) # partner's public KEM key
        self.partner_signature_public_key = base64.b64decode(data['sig_public_key']) # partner's public signing key
        self.partner_username = data['username']
        
        # generate and send the ciphertext and store the shared secret (AES key)
        ciphertext, self.shared_secret = self.kem.encap_secret(partner_kem_public_key)
        #print(f"Generating session key: {base64.b64encode(self.shared_secret)[:20]}")
        
        # Create dictionary payload with the ciphertext to share the key with the partner
        return {
            'type': 'key_share',
            'content': {
                'ciphertext': base64.b64encode(ciphertext).decode()
            }
        }

    # handler for when message type is sign_key
    def extract_sign_key(self, data):
        self.partner_username = data['username']
        self.partner_signature_public_key = base64.b64decode(data['sig_public_key']) # get partner's signature key
        #print(f"Received partner's public signing key: {base64.b64encode(self.partner_signature_public_key)[:20]}")
    
    # handler to get the shared key    
    def handle_key_share(self, data):
        ciphertext = base64.b64decode(data['ciphertext']) # Recover ciphertext
        self.shared_secret = self.kem.decap_secret(ciphertext) 
        #print(f"Receiver got session key: {base64.b64encode(self.shared_secret)[:20]}")
    
    # Encrypt a message using AES-GCM    
    def encrypt_message(self, message):
        try:
            #print("Encrypting message using AES-GCM")
            if not self.shared_secret:
                raise ValueError("No shared secret available")
                
            # Create AESGCM instance from shared secret
            aesgcm = AESGCM(self.shared_secret)
            
            nonce = os.urandom(12) # Generate a random 96-bit (12-byte) nonce
            #additional_data = os.urandom(12)
            additional_data = b"Post Quantum security is here!"  # Use consistent AAD
            # Encrypt the message
            ciphertext = aesgcm.encrypt(
                nonce,
                message.encode(),
                additional_data 
            )
            
            # Create message dictionary
            message_data = {
                'nonce': base64.b64encode(nonce).decode(),
                'aad': base64.b64encode(additional_data).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode()
            }
            #print("Message encrypted successfully")
            # Return JSON string
            return json.dumps(message_data)
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            raise
    
    # Decrypt a message using AES-GCM    
    def decrypt_message(self, encrypted_message):
        try:
            #print("Decrypting message using AES-GCM")
            if not self.shared_secret:
                raise ValueError("No session key available")
                
            # extract the message from JSON string
            try:
                message_data = json.loads(encrypted_message)
                nonce = base64.b64decode(message_data['nonce'])
                additional_data = base64.b64decode(message_data['aad'])
                ciphertext = base64.b64decode(message_data['ciphertext'])
            except (json.JSONDecodeError, KeyError) as e:
                raise ValueError(f"Invalid message format: {e}")
            
            # Create AESGCM instance
            aesgcm = AESGCM(self.shared_secret)
            
            # Decrypt the message
            plaintext = aesgcm.decrypt(
                nonce,
                ciphertext,
                additional_data
            )
            
            #print("Message decrypted successfully")
            return plaintext.decode()
            
        except Exception as e:
            print(f" Decryption error: {str(e)}")
            raise
    
    # Sign a message    
    def sign_message(self, message):
        signature = self.sig.sign(message.encode())
        return base64.b64encode(signature).decode()
    
    # Verify message signature    
    def verify_signature(self, message, signature):
        #print("Verifying message signature")
        try:
            return self.sig.verify(message.encode(), base64.b64decode(signature), self.partner_signature_public_key)
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False

    # Gets the public keys in a dictionary form
    def get_public_keys(self):
        return {
            'kem_public_key': base64.b64encode(self.public_key).decode(),
            'sig_public_key': base64.b64encode(self.signature_public_key).decode()
        }

# Client class
class Client:
    
    # Initialization
    def __init__(self, host, port):
        self.host = host # host
        self.port = port # port number
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # init TCP socket
        self.crypto_manager = CryptoManager() # init a crypto manager

    # Starts a client
    def start(self):
        print('Trying to connect to {}:{}'.format(self.host, self.port))
        self.socket.connect((self.host, self.port)) # connect to server
        print('Successfully connected to {}:{}'.format(self.host, self.port))
        
        # Send public keys to server after connection
        public_keys = self.crypto_manager.get_public_keys()
        data = json.dumps({
            'type': 'init',
            'content': public_keys
        }) + '\n'
        self.socket.sendall(data.encode())

        # Start sending and receiving threads
        send_thread = Send_Thread(self.socket, self.crypto_manager)
        receive_thread = Receive_Thread(self.socket, self.crypto_manager)

        send_thread.start()
        receive_thread.start()

# Main
if __name__ == "__main__":
    client = Client(HOST, PORT)
    client.start()