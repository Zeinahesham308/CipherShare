import socket
import crypto_utils
import os
import filehandler
import time
from crypto_utils import encrypt_file, hash_file, decrypt_file

# ... (Constants for ports, network addresses, file chunk size etc.)
...


class FileShareClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)
        self.rv_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

    def register_with_rendezvous(self, username, rendezvous_server_ip='127.0.0.1', rendezvous_server_port=9000):
        try:

            self.rv_socket.connect((rendezvous_server_ip, rendezvous_server_port))

            # Send REGISTER message with your port and username
            message = f"REGISTER {self.client_socket.getsockname()[1]} {username}"
            self.rv_socket.send(message.encode())
            self.rv_socket.recv(1024)  # Wait for confirmation
            print(f"[Client] Successfully registered as '{username}' with Rendezvous Server.")
            #rv_socket.close()
            return True


        except Exception as e:
            print(f"Error registering with Rendezvous Server: {e}")

    def get_peer_list(self):
        try:
            self.rv_socket.send("LIST".encode())
            peers = self.rv_socket.recv(1024).decode()
            #self.rv_socket.close()
            if peers.strip() == "":
                print("[Client] No other peers found.")
                return []
            peer_list = peers.strip().split("\n")
            print("[Client] Discovered Peers:")
            for peer in peer_list:
                print(f" -> {peer}")
            return peer_list
        except Exception as e:
            print(f"Error retrieving peer list: {e}")
            return []

    def register_user(self, username, password):
        # ... (Implement registration process - send username, hashed  password + salt to a registration service / peer - how to distribute user info in P2P? - Simplification needed, perhaps a   dedicated'user registry' peer initially or file-based for simplicity) ...
        # ... (Client-side password hashing and salt generation) ...
        try:
            self.client_socket.send("REGISTER".encode())

            #  Step 1: Hash the password locally
            hashed_password = crypto_utils.hash_password(password)

            self.client_socket.send(username.encode())
            self.client_socket.send(hashed_password.encode())


            response = self.client_socket.recv(1024).decode()
            if response=="FAILED":
                return False
            else:
                return True
                print(response)


        except Exception as e:
            print(f"Error during registration: {e}")
        pass

    def login_user(self, username, password):

        # ... (Implement login process - send username, password -  server / peer authenticates against stored hashed password - handle session - simplified sessionmanagementfor P2P could be token-basedor direct connectionbased) ...
        # ... (Client-side password hashing to compare against storedhash) ...
        try:

            self.client_socket.send("LOGIN".encode())


            hashed_password = crypto_utils.hash_password(password)


            self.client_socket.send(username.encode())
            self.client_socket.send(hashed_password.encode())


            response = self.client_socket.recv(1024).decode()

            if response == "Login successful.":
                self.username = username

                salt = b'static_salt_for_now'  # Later: retrieve per-user salt from file
                self.session_key = crypto_utils.derive_key_from_password(password, salt)
                self.register_with_rendezvous(self.username)
                return True
            else:
                self.username = None
                return False

        except Exception as e:
            print(f"Error during login: {e}")

    def upload_file(self, filepath):
        """
        Encrypts and uploads a file to the server

        Args:
            filepath (str): Path to the file to upload
        """
        if not self.username:
            print("You must be logged in to upload files.")
            return

        # Check if file exists
        if not os.path.isfile(filepath):
            print(f"Error: File '{filepath}' does not exist.")
            return

        print(f"[Client] Encrypting file: {filepath}")

        # Create temp directory if it doesn't exist
        file_dir = os.path.dirname(filepath)
        temp_dir = os.path.join(file_dir, "temp")
        os.makedirs(temp_dir, exist_ok=True)

        # Generate temp file path
        filename = os.path.basename(filepath)
        temp_path = os.path.join(temp_dir, filename + ".enc")

        try:
            # Encrypt the file
            encrypted_data = encrypt_file(filepath, self.session_key)

            # Save encrypted data to temp file
            with open(temp_path, 'wb') as f:
                f.write(encrypted_data)

            # Generate hash of encrypted file
            file_hash = hash_file(temp_path)
            print(f"[Client] SHA-256 hash of encrypted file: {file_hash}")
            print(f"[Client] Temporary encrypted file saved to: {temp_path}")

            # Start upload process
            command = "UPLOAD"
            self.client_socket.send(command.encode())
            ack_message = self.client_socket.recv(1024).decode()
            print(ack_message)

            # Send username
            self.client_socket.send(self.username.encode())
            username_response = self.client_socket.recv(1024).decode()
            print(username_response)

            # Send filename (original, not the temp one)
            message = f"filename is : {filename}.enc"
            self.client_socket.send(message.encode())

            # Check if server received filename
            filename_response = self.client_socket.recv(1024).decode()
            if filename_response == "RECEIVED":
                self.client_socket.send(file_hash.encode())
            else:
                self.client_socket.send("FAILURE".encode())
                print("Failed to send filename to server")
                return

            print(f"[Client] Original filepath: {filepath}")
            print(f"[Client] Encrypted filepath: {temp_path}")
            print("[Client] Waiting for START signal...")

            message = self.client_socket.recv(1024).decode()
            if message == "START":
                # Send the encrypted file
                with open(temp_path, 'rb') as f:
                    while chunk := f.read(1024):
                        time.sleep(0.01)
                        self.client_socket.sendall(chunk)

                self.client_socket.send(b"END_OF_FILE")

                # Wait for server confirmation
                received_message = self.client_socket.recv(1024).decode()
                print(received_message)

                # Clean up the temporary file
                os.remove(temp_path)
                print(f"[Client] Temporary encrypted file {temp_path} removed.")

                # Try to remove temp directory if empty
                try:
                    os.rmdir(temp_dir)
                    print(f"[Client] Temporary directory removed: {temp_dir}")
                except OSError:
                    # Directory not empty, which is fine
                    pass

        except Exception as e:
            print(f"[Error] Failed to upload file: {str(e)}")
            # Clean up in case of error
            if os.path.exists(temp_path):
                os.remove(temp_path)
                print(f"[Client] Temporary encrypted file {temp_path} removed due to error.")

        # ... (File encryption using crypto_utils, integrity hash generation) ...


    def download_file(self, file_id, destination_path):
        # ... (Request file from peer, receive encrypted chunks, decryptchunks, verify integrity, save file) ...
        if not self.username or not self.session_key:
            print("You must be logged in to download files.")
            return
        command="DOWNLOAD"
        self.client_socket.send(command.encode())
        ack_message=self.client_socket.recv(1024).decode()
        print(ack_message)

        self.client_socket.send(file_id.encode())
        reply=self.client_socket.recv(1024).decode()

        if reply.startswith("ERROR"):
            print("there is no such a file to download")
            print("redirecting you to the options...")
            return

        if reply=="OK":
            expected_hash = self.client_socket.recv(1024).decode()
            print(f"[Client] Expected SHA-256 hash from server: {expected_hash}")

            start_signal = self.client_socket.recv(1024).decode()
            if start_signal != "START":
                print("Did not receive START signal. Aborting.")
                return

            encrypted_path = destination_path + ".enc"
            with open(encrypted_path, 'wb') as f:
                while True:
                    data = self.client_socket.recv(1024)
                    if data == b"END_OF_FILE":
                        break
                    f.write(data)

            print(f"[Client] Encrypted file received at: {encrypted_path}")

            # Verify hash
            actual_hash = hash_file(encrypted_path)
            print(f"[Client] Actual SHA-256 hash: {actual_hash}")

            if actual_hash != expected_hash:
                print("File hash mismatch! File may be corrupted.")
                user_choice = input("Do you want to proceed with decryption anyway? (y/n): ")
                if user_choice.lower() != 'y':
                    print("Download aborted.")
                    os.remove(encrypted_path)
                    return
            else:
                print("File integrity verified. Proceeding to decrypt.")

            try:
                # Try to decrypt the file
                decrypt_file(encrypted_path, self.session_key)
                os.rename(encrypted_path, destination_path)
                print(f"[Client] File decrypted and saved to {destination_path}")
            except Exception as e:
                print(f"Error during decryption: {e}")
                print("The file might be corrupted or using a different encryption key.")
                # Clean up the encrypted file
                os.remove(encrypted_path)

        # ... (File decryption, integrity verification) ...
        pass

    def search_files(self, keyword):
        # ... (Implement file search in the P2P network - broadcasting? Distributed Index? - Simplification required) ...
        self.client_socket.send("SEARCH".encode())
        self.client_socket.send(keyword.encode())

        result = self.client_socket.recv(4096).decode()

        print("\n Search Results:")
        if result == "EMPTY":
            print("No files matched your search.")
        else:
            for file in result.strip().split("\n"):
                print(f" {file}")


    def list_shared_files(self):
            # ... (Keep track of locally shared files and display them)
            self.client_socket.send("LIST".encode())
            file_list = self.client_socket.recv(4096).decode()
            print("\n Shared Files:")
            if file_list == "NOFILES":
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

    # Discover peers automatically
    # available_peers = FSC.discover_peers()
    # print(f"Available peers: {available_peers}")


    #message=FSC.client_socket.recv(1024).decode()
    #print(message)
    choice=''
    while choice != 0:

        print("******** HELLO WELCOME TO CIPHERSHARE  ********  \n - Enter Tagrget number -\n[1]login\n[2]Signup\n[3]Uploading a file\n[4]Downloading a file\n[5]Listing all files\n[6]Searching for a file\n[7]Listing all online peers\n[8]End\n")
        choice=int(input())
        if choice==1:
            if FSC.username:
                print(f"USER \"{FSC.username}\" ALREADY LOGGED IN")
                choice=''
                continue
            print("----------------------LOGIN----------------------")

            username=input("ENTER USERNAME : ")
            password=input("ENTER PASSWORD : ")
            result=FSC.login_user(username,password)
            if result:
                print("LOGIN SUCCESSFUL!")
            else :
                print("User info is wrong or user does not exist")

        elif choice== 2:
            if  FSC.username:
                print(f"USER {FSC.username}ALREADY LOGGED IN")
                choice=''
                continue
            print("----------------------SIGNUP----------------------")
            username=input("ENTER USERNAME : ")
            password=input("ENTER PASSWORD : ")
            result=FSC.register_user(username,password)
            if result:
                print("SIGNUP SUCCESSFULY .... YOU WILL NEED TO LOGIN TO CONTINUE")
            else :
                print("FAILED SIGNUP TRY ANOTHER USERNAME OR VALID PASSWORD")

        elif choice == 3:
            print("Enter path of the file to upload: ")
            filepath=input()
            normalizedfilepath = filehandler.FileHandler.normalize_path(filepath)
            FSC.upload_file(normalizedfilepath)

        elif choice == 4:
            print("enter the filename to download ex :  name.pdf.enc")
            file=input()
            print("enter the destination where you want to save the file to be downloaded\n example C:\\Users\\zeina\\Desktop\\myfiles\\yourfilename")
            dest=input()
            FSC.download_file(file,dest)


        elif choice == 5:
            FSC.list_shared_files()

        elif choice == 6:
            keyword = input("Enter keyword to search for: ")
            FSC.search_files(keyword)
        elif choice ==7 :
            FSC.get_peer_list()

        elif choice==8:
            break;
        else:
            print("Try again and enter a valid number")
        choice = ''




if __name__ == '__main__':
    main()