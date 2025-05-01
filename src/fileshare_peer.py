import socket
import threading
import os
from crypto_utils import encrypt_file, hash_file, decrypt_file
import json
import  time
# ... (Data structures for user info, shared files, peer lists etc.)
...



class FileSharePeer:
    def __init__(self, port):
        self.peer_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.port = port
        self.host = '0.0.0.0'
        self.users = {} # {username: {hashed_password, salt, ...}} - In-memory for simplicity, consider file-based storage for persistence
        self.shared_files = {}  # {file_id: {filepath, owner_username, ...}} - Track files shared by this peer
        #self.handle_client_connection


        # Load users from file if it exists
        if os.path.exists("users.json"):
            with open("users.json", "r") as f:
                self.users = json.load(f)
        else:
            self.users = {}
    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5) #5connections
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
                    username = client_socket.recv(1024).decode()
                    hashed_password = client_socket.recv(1024).decode()

                    if username in self.users:
                        #print(self.users)
                        client_socket.send("FAILED".encode())

                    else:
                        self.users[username] = hashed_password

                        # Save updated users to file
                        with open("users.json", "w") as f:
                            json.dump(self.users, f)

                        client_socket.send("Registration successful.".encode())
                    pass
                elif command== "LOGIN":
                    #Handle login
                    username = client_socket.recv(1024).decode()
                    hashed_password = client_socket.recv(1024).decode()  # password already hashed from client

                    if username in self.users and self.users[username] == hashed_password:
                        client_socket.send("Login successful.".encode())
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
                    pass
                elif command=="LIST":
                    print(f"[Server] Client requested list of shared files.")
                    os.makedirs('shared_files', exist_ok=True)

                    file_paths = []
                    for root, dirs, files in os.walk('shared_files'):
                        for file in files:
                            relative_path = os.path.relpath(os.path.join(root, file), 'shared_files')
                            file_paths.append(relative_path)

                    if not file_paths:
                        client_socket.send("NOFILES".encode())
                        print("NO FILES FOUND")
                    else:
                        file_list = "\n".join(file_paths)
                        client_socket.send(file_list.encode())

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




        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()


def main():
    FSP = FileSharePeer(5555)
    FSP.start_peer()
if __name__ == '__main__':
    main()




