import hashlib
import socket
import threading
import os
from crypto_utils import encrypt_file, hash_file, decrypt_file
import json
import  time
# ... (Data structures for user info, shared files, peer lists etc.)
...

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class FileSharePeer:
    def __init__(self, port=0, username=None):
        self.peer_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.port = port
        self.host = '0.0.0.0'
        self.users = {} # {username: {hashed_password, salt, ...}} - In-memory for simplicity, consider file-based storage for persistence
        self.shared_files = {}  # {file_id: {filepath, owner_username, ...}} - Track files shared by this peer
        #self.handle_client_connection
        self.active_username = username


        # Load users from file if it exists
        if os.path.exists("users.json"):
            with open("users.json", "r") as f:
                self.users = json.load(f)
        else:
            self.users = {}
    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5) #5connections
        self.port = self.peer_socket.getsockname()[1]
        print(f"Peer listening on port {self.port}")
        while True:
            client_socket, client_address = self.peer_socket.accept()
            client_thread = threading.Thread(target=self.handle_client_connection, args=(client_socket, client_address))
            client_thread.start()


    def handle_client_connection(self, client_socket, client_address):
        print(f"Accepted connection from {client_address}")

        try:
            while True:
            # ... (Receive commands from client - register, login, upload, download, search, etc. - define a simple protocol) ...
                #client_socket.send("Server Waiting for the command".encode())
                command = client_socket.recv(1024).decode()  # Example - define command structure
                if command == "REGISTER":
                    data = client_socket.recv(4096).decode()
                    parts = data.split("\n")
                    if len(parts) >= 3:
                        username = parts[0]
                        hashed_password = parts[1]
                        salt = parts[2]
                    else:
                        print("error")
                        return

                    if username in self.users:
                        print(self.users)
                        client_socket.send("FAILED".encode())

                    else:
                        self.users[username] = {
                            "hashed_password": hashed_password,
                            "salt": salt
                        }


                        # Save updated users to file
                        with open("users.json", "w") as f:
                            json.dump(self.users, f)

                        client_socket.send("Registration successful.".encode())
                    pass
                elif command== "LOGIN":
                    #Handle login
                    username = client_socket.recv(1024).decode()
                    if username not in self.users:
                        client_socket.send("NO_USER".encode())
                        continue
                    salt = self.users[username]["salt"]
                    client_socket.send(salt.encode())

                    hashed_password = client_socket.recv(1024).decode()
                    stored_hash = self.users[username]["hashed_password"]

                    if hashed_password == stored_hash:
                        client_socket.send("Login successful.".encode())
                        self.active_username = username
                    else:
                        client_socket.send("Invalid credentials.".encode())

                elif command=="UPLOAD":
                    os.makedirs('shared_files', exist_ok=True)

                    message = "Waiting for your upload..."
                    client_socket.send(message.encode())

                    username = client_socket.recv(1024).decode()
                    client_socket.send("USERNAME RECEIVED".encode())

                    # Create a folder for that user if it doesn't exist
                    user_folder = os.path.join('shared_files', username)
                    os.makedirs(user_folder, exist_ok=True)

                    received_message = client_socket.recv(1024).decode()

                    filename = received_message.split("filename is : ")[1].strip()
                    print(f"File name received is {filename}")

                    client_socket.send("RECEIVED".encode())
                    message=client_socket.recv(1024).decode()
                    if message=="FAILURE":
                        print(" file hash is not RECEIVED")
                    else:
                        expected_hash = message
                        print(f"[Server] Received expected file hash: {expected_hash}")

                        filepath = os.path.join(user_folder, filename)
                        client_socket.send("START".encode())


                        with open(filepath, 'wb') as f:
                            while True:
                                data = client_socket.recv(1024)
                                if data == b"END_OF_FILE":
                                    break
                                f.write(data)

                        print(f"[Server] File '{filename}' received and saved to {filepath}.")


                        actual_hash = hash_file(filepath)
                        print(f"[Server] Actual hash:   {actual_hash}")
                        print(f"[Server] Expected hash: {expected_hash}")

                        if actual_hash == expected_hash:
                            print("File integrity verified.")
                        else:
                            print("WARNING: Hash mismatch...!!! Upload may be corrupted!!.")


                        # You can also register the file here for later use
                        self.shared_files[filename] = {
                            "filepath": filepath,
                            "owner": username
                        }

                        message = "file uploaded successfully"
                        client_socket.send(message.encode())



                elif command =="DOWNLOAD":

                    message="you can  download now..."
                    client_socket.send(message.encode())


                    filename=client_socket.recv(1024).decode()
                    print(f"file to be downlaoded is : {filename}")



                    filepath = None
                    for root, dirs, files in os.walk("shared_files"):
                        if filename in files:
                            filepath = os.path.join(root, filename)
                            print(filepath)
                            break

                    if not filepath or not os.path.exists(filepath):
                        client_socket.send(f"ERROR: File '{filename}' not found.".encode())
                        return

                    #filepath = os.path.join("shared_files", filename)


                    client_socket.send("OK".encode())  # confirm file is ready
                    time.sleep(0.05)
                    file_hash = hash_file(filepath)
                    client_socket.send(file_hash.encode())  # send hash first
                    print(f"[Server] Sent hash: {file_hash}")

                    time.sleep(0.05)
                    client_socket.send("START".encode())
                    print("[Server] Sending file...")


                    with open(filepath, 'rb') as f:
                        while chunk := f.read(1024):
                            time.sleep(0.01)
                            client_socket.sendall(chunk)
                    client_socket.send(b"END_OF_FILE")

                    print(f"File '{filename}' sent to requester.")


                    #handle upload
                elif command == "DOWNLOAD_DIST":
                    client_socket.send("you can download now...".encode())

                    filename = client_socket.recv(1024).decode()
                    print(f"file to be downloaded is : {filename}")

                    # 🌟 Receive the session key from client
                    self.session_key = client_socket.recv(1024)
                    if len(self.session_key) not in (16, 24, 32):  # AES key lengths
                        client_socket.send("ERROR: Invalid session key length.".encode())
                        return

                    filepath = None
                    for root, dirs, files in os.walk("shared_files"):
                        if filename in files:
                            filepath = os.path.join(root, filename)
                            print(filepath)
                            break

                    if not filepath or not os.path.exists(filepath):
                        client_socket.send(f"ERROR: File '{filename}' not found.".encode())
                        return

                    client_socket.send("OK".encode())  # confirm file is ready
                    time.sleep(0.05)

                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    from cryptography.hazmat.backends import default_backend

                    with open(filepath, 'rb') as f:
                        data = f.read()

                    iv = os.urandom(16)
                    client_socket.send(iv)  # Send IV first

                    cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
                    encryptor = cipher.encryptor()

                    pad_len = 16 - len(data) % 16
                    data += bytes([pad_len] * pad_len)

                    encrypted = encryptor.update(data) + encryptor.finalize()

                    # Hash the actual encrypted bytes you will send
                    file_hash = hashlib.sha256(encrypted).hexdigest()
                    client_socket.send(file_hash.encode())  # send hash of encrypted data

                    time.sleep(0.05)
                    client_socket.send("START".encode())
                    print("[Server] Sending file...")

                    # Now send the encrypted data in chunks
                    for i in range(0, len(encrypted), 1024):
                        print("#", end='', flush=True)
                        chunk = encrypted[i:i + 1024]
                        time.sleep(0.01)
                        client_socket.sendall(chunk)

                    client_socket.send(b"END_OF_FILE")
                    print(f"\n[Server] Sent {len(encrypted)} bytes in chunks.")
                    print(f"File '{filename}' sent to requester.")


                elif command == "LIST":
                    if not self.active_username:
                        client_socket.send("NOFILES".encode())
                        return

                    user_dir = os.path.join("shared_files", self.active_username)
                    file_paths = []

                    if os.path.exists(user_dir):
                        for root, dirs, files in os.walk(user_dir):
                            for file in files:
                                relative_path = os.path.relpath(os.path.join(root, file), "shared_files")
                                file_paths.append(relative_path)

                    response = "\n".join(file_paths) if file_paths else "NOFILES"
                    client_socket.send(response.encode())

                elif command == "SEARCH":
                    keyword = client_socket.recv(1024).decode().strip()
                    print(f"[Server] Searching for: {keyword}")

                    os.makedirs('shared_files', exist_ok=True)

                    matches = []
                    for root, dirs, files in os.walk('shared_files'):
                        for file in files:
                            if keyword.lower() in file.lower():
                                relative_path = os.path.relpath(os.path.join(root, file), 'shared_files')
                                matches.append(relative_path)

                    if matches:
                        response = "\n".join(matches)
                    else:
                        response = "EMPTY"

                    client_socket.send(response.encode())


                elif command == "SEARCH_DIST":

                    keyword = client_socket.recv(1024).decode().strip()

                    print(f"[Server] Received distributed search for: {keyword}")
                    #print(self.active_username)
                    if not self.active_username:
                        client_socket.send("I DONT HAVE".encode())
                        return

                    peer_folder = os.path.join("shared_files", self.active_username)

                    if not os.path.exists(peer_folder):
                        client_socket.send("I DONT HAVE".encode())

                        return

                    matches = []

                    for root, dirs, files in os.walk(peer_folder):

                        for file in files:

                            if keyword.lower() in file.lower():
                                relative_path = os.path.relpath(os.path.join(root, file), 'shared_files')

                                matches.append(relative_path)

                    response = "\n".join(matches) if matches else "I DONT HAVE"

                    client_socket.send(response.encode())
                    return





        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()


def main():
    FSP = FileSharePeer(port=0)
    FSP.start_peer()
if __name__ == '__main__':
    main()



