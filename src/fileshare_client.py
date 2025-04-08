import socket
import crypto_utils
import os
import filehandler

# ... (Constants for ports, network addresses, file chunk size etc.)
...


class FileShareClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)
        self.username = None
        self.session_key = None  # For symmetric encryption with peers

    def connect_to_peer(self, peer_address):
        try:
            self.client_socket.connect(peer_address)
            print(f"Connected to peer at {peer_address}")
            return True
        except Exception as e:
            print(f"Error connecting to peer {peer_address}: {e}")
            return False

    def register_user(self, username, password):
        # ... (Implement registration process - send username, hashed  password + salt to a registration service / peer - how to distribute user info in P2P? - Simplification needed, perhaps a   dedicated'user registry' peer initially or file-based for simplicity) ...
        # ... (Client-side password hashing and salt generation) ...
        pass

    def login_user(self, username, password):

        # ... (Implement login process - send username, password -  server / peer authenticates against stored hashed password - handle session - simplified sessionmanagementfor P2P could be token-basedor direct connectionbased) ...
        # ... (Client-side password hashing to compare against storedhash) ...
         pass

    def upload_file(self, filepath):
        # ... (Read file in chunks, encrypt chunks, send chunks to  peer - need to implement P2P filetransfer protocol - simplified) ...
        command="UPLOAD"
        self.client_socket.send(command.encode())
        ack_message=self.client_socket.recv(1024).decode()
        print(ack_message)

        filename = os.path.basename(filepath)
        message=f"filename is : {filename}"
        self.client_socket.send(message.encode())
        print(f"filepath is:{filepath}")
        counter=0
        with open(filepath, 'rb') as f:
            while chunk := f.read(1024):
                print("send")
                print (counter)
                counter+=1
                self.client_socket.send(chunk)
        self.client_socket.send(b"END_OF_FILE")
        received_message=self.client_socket.recv(1024).decode()
        print(received_message)

        # ... (File encryption using crypto_utils, integrity hash generation) ...


    def download_file(self, file_id, destination_path):
        # ... (Request file from peer, receive encrypted chunks, decryptchunks, verify integrity, save file) ...
        command="DOWNLOAD"
        self.client_socket.send(command.encode())
        ack_message=self.client_socket.recv(1024).decode()
        print(ack_message)
        self.client_socket.send(file_id.encode())
        reply=self.client_socket.recv(1024).decode()
        if reply.startswith("ERROR"):
            print("there is no such a file to download")
            print("redirecting you to the options...")
        if reply=="OK":
            with open(destination_path, 'wb') as f:
                while True:
                    data = self.client_socket.recv(1024)
                    if data == b"END_OF_FILE":
                        break
                    f.write(data)
            print("[Client] File downloaded and saved to", destination_path)


        # ... (File decryption, integrity verification) ...
        pass

    def search_files(self, keyword):
        # ... (Implement file search in the P2P network - broadcasting? Distributed Index? - Simplification required) ...
        self.client_socket.send("SEARCH".encode())
        self.client_socket.send(keyword.encode())

        result = self.client_socket.recv(4096).decode()

        print("\n Search Results:")
        if result.strip() == "":
            print("No files matched your search.")
        else:
            for file in result.strip().split("\n"):
                print(f" {file}")
        pass

    def list_shared_files(self):
            # ... (Keep track of locally shared files and display them)
            self.client_socket.send("LIST".encode())
            file_list = self.client_socket.recv(4096).decode()
            print("\n Shared Files:")
            if file_list.strip() == "":
                print("No files are currently shared.")
            else:
                for file in file_list.strip().split("\n"):
                    print(f" {file}")
            ...
            pass

    # ... (Methods for P2P message handling, network discovery - simplified) ...

# ... (Client program entry point, user interface loop) ...
def main():
    FSC = FileShareClient()
    FSC.connect_to_peer(('127.0.0.1', 5555))
    #message=FSC.client_socket.recv(1024).decode()
    #print(message)
    choice=''
    while choice != 0:

        print("Choose 1 for uploading a file , 2 for downloading a file , 3 for listing all files and 4 for searching")
        choice=int(input())
        if choice == 1:
            print("Enter path of the file to upload: ")
            filepath=input()
            normalizedfilepath = filehandler.FileHandler.normalize_path(filepath)
            FSC.upload_file(normalizedfilepath)
        if choice == 2:
            print("enter the filename to download")
            file=input()
            print("enter the destination where you want to save the file to be downloaded")
            dest=input()
            FSC.download_file(file,dest)

        if choice == 3:
            FSC.list_shared_files()
        if choice == 4:
            keyword = input("Enter keyword to search for: ")
            FSC.search_files(keyword)





if __name__ == '__main__':
    main()