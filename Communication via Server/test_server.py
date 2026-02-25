''' IMPORTS '''
import socket
import os
import threading
import json

# Network configuration
HOST = '127.0.0.1'
PORT = 65432

# Client Handler thread
class Client_Handler(threading.Thread):
    
    # Initialization
    def __init__(self, client, server):
        super().__init__() # init for threading
        self.client = client # Client socket
        self.server = server # server object
        self.username = None # Client's username
        self.chat_partner = None # Chat partner
        
        # Client's public keys
        self.kem_public_key = None
        self.sig_public_key = None
        
        # Message buffer
        self.buffer = ""
    
    # The main loop    
    def run(self):
        
        # Loop forever
        while True:
            try:
                
                data = self.client.recv(1024).decode() # receive incoming data
                if not data:
                    break
                
                # add data to buffer
                self.buffer += data 
                
                # Loop over buffer until no new line character is reached
                while '\n' in self.buffer:
                    
                    # Read line by line
                    line, self.buffer = self.buffer.split('\n', 1)
                    
                    try:
                        msg_data = json.loads(line) # Recovers dictionary from JSON string
                        msg_type = msg_data.get('type', '') # Get the message type, if none default to empty
                        
                        ### MESSAGE TYPE CHECKS ###
                        match msg_type:
                            
                            case 'init': # INITIALIZATION CASE
                                try:
                                    self.process_initial_connection(msg_data['content'])
                                except Exception as e:
                                    print(f"Error receiving initial keys: {e}")
                                    print(f"Buffer content: {self.buffer}")
                                self.get_username()
                                self.show_menu()
                                
                            case 'command': # COMMAND CASE
                                if not self.handle_command(msg_data['content']):
                                    break
                                
                            case 'key_share': # KEY SHARE CASE
                                if self.chat_partner:
                                    self.server.forward_key(self.chat_partner, msg_data)
                                else:
                                    print(f"No chat partner for key share from {self.username}")
                                    
                            case 'chat': # CHAT CASE
                                if self.chat_partner:
                                    self.server.send_private_message(self.chat_partner, msg_data)
                                else:
                                    print(f"No chat partner for message from {self.username}")
                                    
                            case _: # DEFAULT CASE
                                print(f"Unknown message type: {msg_type}")
                                
                    except Exception as e:
                        print(f"JSON error: {e}")       
            except Exception as e:
                print(f"Error handling message: {e}")
                break

        # Close client connection
        print(f"Client {self.username} disconnecting")
        self.disconnect_from_chat(quitting=True)
        self.server.remove_connection(self)
        try:
            self.client.close()
        except:
            pass

    # Gets the public keys
    def process_initial_connection(self, contents):
        self.kem_public_key = contents['kem_public_key']
        self.sig_public_key = contents['sig_public_key']
        #print(f"KEM key: {self.kem_public_key[:30]}...")
        #print(f"SIG key: {self.sig_public_key[:30]}...")
    
    # Handles command messages  
    def handle_command(self, message):
        #print(f"Handling command: {message}")
        if message.startswith("/menu"):
            self.show_menu()
        elif message.startswith("/list"):
            self.show_users()
        elif message.startswith("/connect"):
            try:
                _, target_user = message.split(" ", 1) # get username
                target_user = target_user.strip() # remove any leading/trailing whitespace
                self.connect_to_user(target_user) # connect users
            except ValueError:
                self.send_json('system', "Usage: /connect <username>")
        elif message.startswith("/disconnect"):
            self.disconnect_from_chat()
        elif message == "/quit":
            return False
        return True
    
    # Prompt the client for a username
    def get_username(self):
        self.send_json('system', "Enter your username: ")
        while True:
            try:
                # Receive username
                message = self.client.recv(1024).decode().strip()
            
                # Try to parse as JSON in case client sends formatted message
                username = message.strip()
                
                # Username can't be empty
                if not username:
                    self.send_json('system', "Username cannot be empty. Please choose a username: ")
                    continue
                
                # Check if username is taken
                if self.server.is_username_taken(username):
                    self.send_json('system', f"Username '{username}' is already taken. Please choose another: ")
                
                else: # add username
                    self.username = username
                    self.server.add_username(username)
                    welcome = f"Welcome, {username}!"
                    self.send_json('system', welcome)
                    break
                
            except Exception as e:
                print(f"Error in get_username: {e}")
                return
    
    # Show the menu options
    def show_menu(self):
        menu = "\nAvailable commands:\n"
        menu += "/list - Show online users\n"
        menu += "/connect <username> - Connect to a user\n"
        menu += "/disconnect - Disconnect from current chat\n"
        menu += "/menu - Show this menu\n"
        menu += "/quit - Exit the chat\n"
        self.send_json('system', menu)
    
    # Shows other users to connect with
    def show_users(self):
        # get list of users
        users = self.server.get_available_users(self.username)
        if not users:
            self.send_json('system', "No other users are online.")
        else:
            user_list = "Online users:\n" + "\n".join(users)
            self.send_json('system', user_list)
    
    # Tries to connect the user with the target
    def connect_to_user(self, target_user):
        
        # Already in a chat
        if self.chat_partner:
            self.send_json('system', "You are already in a chat. Use /disconnect first.")
            return
        
        print(f"Connection request from {self.username} to {target_user}") # Debug print
        #print(f"Available users: {self.server.get_available_users(self.username)}") # Debug print
        
        # Check user exits
        if not self.server.is_username_taken(target_user):
            self.send_json('system', f"User '{target_user}' not found.")
            return
        
        # Get the target user's Client Handler
        target_handler = self.server.get_client_handler(target_user)
        
        # check if valid client handler
        if not target_handler:
            self.send_json('system', f"Could not establish connection with '{target_user}'.")
            return
        
        # Check if target already in a chat
        if target_handler.chat_partner:
            self.send_json('system', f"User '{target_user}' is already in a chat.")
            return
        
        ### Connect Users ### 
        # Exchange public keys through server
        try:
            
            # Set chat partners
            self.chat_partner = target_user
            target_handler.chat_partner = self.username
            
            # Send 'self' (client who made connection request) public keys to target
            print(f"Sending {self.username}'s public keys to recipient {target_user}")
            # Send target's public keys to initiator
            target_handler.send_json('public_keys', {
                'kem_public_key': self.kem_public_key,
                'sig_public_key': self.sig_public_key,
                'username': self.username
            })
            
            # Send target user keys to 'self' (client who made connection request)
            print(f"Sending {target_user}'s public signing key to recipient {self.username}")
            # Send initiator's public keys to target (not initiator)
            self.send_json('sign_key', {
                'sig_public_key': target_handler.sig_public_key,
                'username': target_handler.username
            })
            
            self.send_json('system', f"Connection established with {target_user}. Start chatting!")
            target_handler.send_json('system', f"{self.username} has connected to chat with you.")
            
        except Exception as e:
            print(f"Error: {e}")
            self.send_json('system', "Failed to establish connection.")
            return
    
    # Disconnects the users from a chat
    def disconnect_from_chat(self, quitting=False):
        if self.chat_partner: # Check if they have a chat partner
            partner_handler = self.server.get_client_handler(self.chat_partner)
            if partner_handler: # Reset chat partner
                try:
                    partner_handler.send_json('system', f"{self.username} has disconnected.")
                    partner_handler.send_json('close_chat', "")
                    partner_handler.chat_partner = None
                    partner_handler.show_menu()
                except:
                    pass
            
            if not quitting:
                try:
                    # Reset user
                    self.chat_partner = None
                    self.send_json('system', "Disconnected from chat.")
                    self.send_json('close_chat', "")
                    self.show_menu()
                except Exception:
                    pass
    
    # Message parser to JSON
    def send_json(self, msg_type, content, signature=None):
        try:
            message = {
                'type': msg_type,
                'content': content
            }
            if signature:
                message['signature'] = signature
                
            message_str = json.dumps(message) + '\n'
            #print(f"Sending message to client: {message_str[:100]}...")
            self.client.sendall(message_str.encode())
        except Exception as e:
            print(f"Error sending message: {e}")

# The server thread
class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__() # init for threading
        self.host = host 
        self.port = port
        self.connections_list = [] # list of connected users
        self.usernames = set() # username set
    
    # Main loop
    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # init TCP socket
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # make it reusable
        self.sock.bind((self.host, self.port)) # bind socket with port
        self.sock.listen(1) # listen for connections
        print('Listening on', self.sock.getsockname())
        
        # loop forever
        while True:
            client, address = self.sock.accept() # accept incoming connections
            print('Accepted a new connection from {}'.format(address))
            client_handler = Client_Handler(client, self) # create a client handler for client
            client_handler.start()
            self.connections_list.append(client_handler) # add client to list
    
    # Gets users not in a chat
    def get_available_users(self, excluding_username):
        usernames = []
        for users in self.connections_list:
            # Check if users has a username and it's not the one excluded
            if users.username and users.username != excluding_username:
                usernames.append(users.username)
        return usernames
    
    # Gets the client_handler object for a user
    def get_client_handler(self, username):
        #print(f"Looking for handler for {username}")
        for handler in self.connections_list:
            if handler.username and handler.username == username:
                return handler
        return None
    
    # Forwards the key
    def forward_key(self, to_user, message_data):
        #print(f"Forwarding key from from {from_user} to {to_user}")
        target_handler = self.get_client_handler(to_user)
        if target_handler:
            try:
                # Don't modify the encrypted content, just forward it
                target_handler.send_json('key_share', message_data['content'])
                #print(f"Key forwarded successfully to {to_user}")
            except Exception as e:
                print(f"Error forwarding key: {e}")
        else:
            print(f"Could not find handler for {to_user}")
    
    # Forwards messages between clients       
    def send_private_message(self, to_user, message_data):
        #print(f"Attempting to send message from {from_user} to {to_user}")
        target_handler = self.get_client_handler(to_user)
        if target_handler:
            try:
                # Don't modify the encrypted content, just forward it
                message = {
                    'type': 'chat',
                    'content': message_data['content']
                }
                
                if 'signature' in message_data: # Case for signature
                    message['signature'] = message_data['signature']
                    
                target_handler.send_json('chat', message_data['content'], message_data.get('signature'))
                #print(f"Message sent successfully to {to_user}")
            except Exception as e:
                print(f"Error sending message: {e}")
        else:
            print(f"Could not find handler for {to_user}")
    
    # Adds username to list
    def add_username(self, username):
        self.usernames.add(username)

    # Checks if username is taken
    def is_username_taken(self, username):
        return username in self.usernames
    
    # Remove client from connnects
    def remove_connection(self, connection):
        if connection in self.connections_list:
            self.connections_list.remove(connection)
            if connection.username:
                self.usernames.remove(connection.username)

# Exit condition thread for to close the server
def close_server(server):
    while True:
        server_input = input('>')
        if server_input == 'q':
            print('Closing all connections...')
            for connection in server.connections_list:
                connection.client.close()
            print('Shutting down the server...')
            os._exit(0)

if __name__ == "__main__":
    # Starts the server
    server = Server(HOST, PORT)
    server.start()
    
    # Starts exit condition thread
    exit_condition = threading.Thread(target=close_server, args=(server,))
    exit_condition.start()