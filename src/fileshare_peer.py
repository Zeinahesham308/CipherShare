import socket
import threading
import crypto_utils
import os
import json
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
                        print(self.users)
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
                    message="Waiting for your upload..."
                    client_socket.send(message.encode())
                    received_message=client_socket.recv(1024).decode()
                    print(received_message)
                    filename = received_message.split("filename is : ")[1].strip()
                    with open(os.path.join('shared_files', filename), 'wb') as f:
                        counter=0
                        while True:
                            # print("recv")
                            # print(counter)
                            #counter+=1
                            data = client_socket.recv(1024)
                            if data == b"END_OF_FILE":
                                break
                            f.write(data)

                    print("[Receiver] File received and saved.")
                    message="file uploaded successfully"
                    client_socket.send(message.encode())
                    #handle upload



                elif command =="DOWNLOAD":
                    message="you can  download now..."
                    client_socket.send(message.encode())
                    filename=client_socket.recv(1024).decode()
                    print(f"file to be downlaoded is : {filename}")

                    filepath = os.path.join("shared_files", filename)

                    if not os.path.exists(filepath):
                        client_socket.send(f"ERROR: File '{filename}' not found.".encode())
                        return
                    client_socket.send("OK".encode())  # confirm file is ready
                    with open(filepath, 'rb') as f:
                        while chunk := f.read(1024):
                            client_socket.sendall(chunk)
                    client_socket.send(b"END_OF_FILE")

                    print(f"File '{filename}' sent to requester.")


                    #handle upload
                    pass
                elif command=="LIST":
                    print(f"[Server] Client requested list of shared files.")
                    os.makedirs('shared_files', exist_ok=True)  # Make sure folder exists

                    files = os.listdir('shared_files')
                    if not files:
                        client_socket.send("NOFILES".encode())  # send empty string
                        print("NOOO")
                    else:
                        file_list = "\n".join(files)
                        client_socket.send(file_list.encode())

                elif command == "SEARCH":
                    keyword = client_socket.recv(1024).decode().strip()
                    print(f"[Server] Searching for: {keyword}")
                    os.makedirs('shared_files', exist_ok=True)
                    files = os.listdir('shared_files')
                    matches = [f for f in files if keyword.lower() in f.lower()]
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




