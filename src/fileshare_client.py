import socket
import crypto_utils
import os
import filehandler
import time
from crypto_utils import encrypt_file, hash_file, decrypt_file,hash_password_with_salt
from crypto_utils import load_and_decrypt_credentials, generate_fernet_key_from_password
from crypto_utils import encrypt_and_save_credentials
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from fileshare_peer import FileSharePeer
import threading

# ... (Constants for ports, network addresses, file chunk size etc.)
...
import base64

class FileShareClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)
        self.rv_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.session_key = None  # For symmetric encryption with peers
        self.my_peer_port=None

    def connect_to_peer(self, peer_address):
        try:
            self.client_socket.connect(peer_address)
            print(f"Connected to peer at {peer_address}")
            return True
        except Exception as e:
            print(f"Error connecting to peer {peer_address}: {e}")
            return False
    def connect_to_me(self,my_peer_port):
        host_port_str = "127.0.0.1"+":"+str(my_peer_port)
        ip, port_str = host_port_str.split(":")
        address = (ip, int(port_str))
        try:
            self.client_socket.connect(address)
            print(f"Connected to peer at {address}")
            return True
        except Exception as e:
            print(f"Error connecting to peer {address}: {e}")
            return False

    def broadcast_file_search(self, filename):
        results = []
        peer_list = self.get_peer_list()

        for peer_info in peer_list:
            try:
                ip_port = peer_info.split(" ")[0]
                ip, port = ip_port.split(":")
                port = int(port)

                # Create a temporary connection to each peer
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((ip, port))
                    s.send("SEARCH_DIST".encode())
                    time.sleep(0.05)
                    s.send(filename.encode())

                    result = s.recv(4096).decode()
                    if result != "I DONT HAVE":
                        print(f"[{ip}:{port}] has:")
                        for line in result.strip().split('\n'):
                            print(f"  {line}")
                            results.append((ip, port, line))  # line = username:relative_path
                    else:
                        print(f"[{ip}:{port}] does not have the file.")
                    s.close()
            except Exception as e:
                print(f"[Search] Failed to contact {peer_info}: {e}")

        return results

    def start_local_peer(self,username):
        # Let OS assign an available port
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(('localhost', 0))
        assigned_port = temp_sock.getsockname()[1]
        temp_sock.close()

        # Now start the peer on that port
        peer =FileSharePeer(port=assigned_port, username=username)
        threading.Thread(target=peer.start_peer, daemon=True).start()
        print(f"[Client] Started local peer on dynamic port {assigned_port}")

        # Save the port for later use (e.g., registration with rendezvous)
        self.my_peer_port = assigned_port


    def register_with_rendezvous(self, username, rendezvous_server_ip='127.0.0.1', rendezvous_server_port=9000):
        try:

            self.rv_socket.connect((rendezvous_server_ip, rendezvous_server_port))

            # Send REGISTER message with your port and username
            message = f"REGISTER {self.my_peer_port} {username}"
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

            # Generate secure password hash + salt
            hashed_password, salt = crypto_utils.hash_password_with_salt(password)

            self.client_socket.send(username.encode())
            self.client_socket.send(hashed_password.encode())
            self.client_socket.send(salt.encode())

            response = self.client_socket.recv(1024).decode()
            return response != "FAILED"

        except Exception as e:
            print(f"Error during registration: {e}")
            return False

    def login_user(self, username, password):

        # ... (Implement login process - send username, password -  server / peer authenticates against stored hashed password - handle session - simplified sessionmanagementfor P2P could be token-basedor direct connectionbased) ...
        # ... (Client-side password hashing to compare against storedhash) ...
        try:

            self.client_socket.send("LOGIN".encode())
            self.client_socket.send(username.encode())

            salt = self.client_socket.recv(1024).decode()
            if salt == "NO_USER":
                print("User not found.")
                return False

            hashed_password = crypto_utils.derive_hash_with_existing_salt(password, salt)
            self.client_socket.send(hashed_password.encode())


            response = self.client_socket.recv(1024).decode()
            if response == "Login successful.":
                self.username = username
                self.session_key = crypto_utils.derive_key_from_password(password, salt)
                self.register_with_rendezvous(self.username)
                local_salt = os.urandom(16)
                fernet_key = generate_fernet_key_from_password(password, local_salt)

                data_to_save = {
                    "username": username,
                    "salt": salt,
                    "session_key": base64.b64encode(self.session_key).decode()
                }

                cred_file = f"client_credentials_{username}.enc"
                salt_file = f"salt_{username}.bin"

                encrypt_and_save_credentials(cred_file, data_to_save, fernet_key)
                with open(salt_file, 'wb') as sfile:
                    sfile.write(local_salt)

                return True
            else:
                self.username = None
                return False

        except Exception as e:
            print(f"Error during login: {e}")
            return False

    def get_download_path(self,username, filename):
        user_folder = os.path.join("shared_files", username)
        os.makedirs(user_folder, exist_ok=True)
        return os.path.join(user_folder, filename)

    def distributed_download(self,download=True):
        filename = input("Enter filename to search: ")
        peers_with_file = self.broadcast_file_search(filename)

        if not peers_with_file:
            print("No peer has the file.")
            return

        all_files = []
        for ip, port, files in peers_with_file:
            for file in files.strip().split('\n'):
                all_files.append((ip, port, file))

        print("\nAvailable sources:")
        for i, (ip, port, file) in enumerate(all_files):
            print(f"[{i}] {ip}:{port} -> {file}")
        if not download:
            return
        choice = int(input("Select the file number to download from: "))
        ip, port, selected_file = all_files[choice]

        if ":" in selected_file:
            filename = selected_file.split(":", 1)[1].split(os.sep)[-1]
        else:
            filename = os.path.basename(selected_file)

        download_path = os.path.join("shared_files", self.username)
        os.makedirs(download_path, exist_ok=True)
        decrypted_filepath = os.path.join(download_path, filename)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                s.send("DOWNLOAD_DIST".encode())
                time.sleep(0.1)
                s.recv(1024)  # ack

                s.send(filename.encode())
                time.sleep(0.05)
                s.send(self.session_key)

                reply = s.recv(1024).decode()
                if reply.startswith("ERROR"):
                    print("File not found.")
                    return

                expected_hash = s.recv(1024).decode()
                s.recv(1024)  # START

                iv = s.recv(16)
                cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                with open(decrypted_filepath, 'wb') as f:
                    buffer = b""
                    while True:
                        data = s.recv(1024)
                        if data == b"END_OF_FILE":
                            break
                        buffer += data
                        while len(buffer) >= 16:
                            chunk = buffer[:16]
                            buffer = buffer[16:]
                            decrypted_chunk = decryptor.update(chunk)
                            f.write(decrypted_chunk)

                    final = decryptor.finalize()
                    if final:
                        f.write(final)

            actual_hash = hash_file(decrypted_filepath)
            if actual_hash != expected_hash:
                print("[WARNING] File hash mismatch! The file may be corrupted.")
            else:
                print("[Client] File downloaded and integrity verified at:", decrypted_filepath)

        except Exception as e:
            print(f"[Client] Error during download: {e}")

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


    # ... (Methods for P2P message handling, network discovery - simplified) ...

# ... (Client program entry point, user interface loop) ...
def main():
    FSC = FileShareClient()

    print("Enter your username:")
    username = input("Username: ")

    cred_file = f"client_credentials_{username}.enc"
    salt_file = f"salt_{username}.bin"

    if os.path.exists(cred_file) and os.path.exists(salt_file):
        print("Found saved credentials. Enter master password to unlock:")
        master_password = input("Master Password: ")

        with open(salt_file, 'rb') as sfile:
            local_salt = sfile.read()

        fernet_key = generate_fernet_key_from_password(master_password, local_salt)

        try:
            creds = load_and_decrypt_credentials(cred_file, fernet_key)
            FSC.username = creds['username']
            FSC.session_key = base64.b64decode(creds['session_key'])
            peer_thread = threading.Thread(target=FSC.start_local_peer,args=(username,), daemon=True)
            peer_thread.start()
            time.sleep(1.5)
            FSC.register_with_rendezvous(FSC.username)
            print(f"[Auto-login] Welcome back, {FSC.username}")
        except Exception as e:
            print(f"Decryption failed: {e}")
            peer_thread = threading.Thread(target=FSC.start_local_peer,args=(username,), daemon=True)
            peer_thread.start()
            time.sleep(1.5)
    else:
        print("credentials not found need to login or signup")
        peer_thread = threading.Thread(target=FSC.start_local_peer, daemon=True)
        peer_thread.start()
        time.sleep(1.5)
    FSC.connect_to_me(FSC.my_peer_port)
    # ========== MAIN MENU ==========
    choice = ''
    while choice != 0:
        print("\n******** HELLO WELCOME TO CIPHERSHARE ********")
        print(" - Enter Target Number -")
        print("[1] Login\n[2] Signup\n[3] Upload a File\n[4] Download a File\n[5] List Shared Files\n[6] Search for File\n[7] List Online Peers\n[8] End")
        choice = int(input())

        if choice == 1:
            if FSC.username:
                print(f"USER \"{FSC.username}\" ALREADY LOGGED IN")
                continue
            username = input("ENTER USERNAME: ")
            password = input("ENTER PASSWORD: ")
            if FSC.login_user(username, password):
                print("LOGIN SUCCESSFUL!")
            else:
                print("User info is wrong or user does not exist")

        elif choice == 2:
            if FSC.username:
                print(f"USER {FSC.username} ALREADY LOGGED IN")
                continue
            username = input("ENTER USERNAME: ")
            password = input("ENTER PASSWORD: ")
            if FSC.register_user(username, password):
                print("SIGNUP SUCCESSFUL. Please login to continue.")
            else:
                print("FAILED SIGNUP. Try another username or valid password.")

        elif choice == 3:
            filepath = input("Enter path of the file to upload: ")
            normalized = filehandler.FileHandler.normalize_path(filepath)
            FSC.upload_file(normalized)

        elif choice == 4:
            # file = input("Enter the filename to download (e.g., name.pdf.enc): ")
            # dest = input("Enter the destination path: ")
            # FSC.download_file(file, dest)
            FSC.distributed_download()


        elif choice == 5:
            FSC.list_shared_files()

        elif choice == 6:
            FSC.distributed_download(False)
        elif choice ==7 :
            FSC.get_peer_list()

        elif choice==8:
            break;
        # elif choice == 9:
        #     FSC.distributed_download()

        else:
            print("Try again and enter a valid number")
        choice = ''




if __name__ == '__main__':
    main()