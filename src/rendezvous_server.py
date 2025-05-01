import socket
import threading

connected_peers = []  # List of dictionaries: [{'ip': ..., 'port': ..., 'username': ...}]

def handle_peer(peer_socket, addr):
    print(f"[Rendezvous] Peer connected: {addr}")
    peer_info = None

    try:
        while True:
            data = peer_socket.recv(1024).decode()
            if not data:
                break

            if data == "LIST":

                # Send back the list of other connected peers (exclude the requester)
                peers_list = "\n".join([
                    f"{peer['ip']}:{peer['port']} ({peer['username']})"
                    for peer in connected_peers
                    if peer_info is None or (peer['ip'], peer['port']) != (peer_info['ip'], peer_info['port'])
                ])
                if not peers_list.strip():
                    print("[Rendezvous] No other peers to send.")
                    peer_socket.send("NO_PEERS".encode())
                else:
                    peer_socket.send(peers_list.encode())

            elif data.startswith("REGISTER"):
                parts = data.split()
                if len(parts) == 3:
                    _, port, username = parts
                    peer_info = {
                        'ip': addr[0],
                        'port': int(port),
                        'username': username
                    }
                    connected_peers.append(peer_info)
                    peer_socket.send("REGISTERED".encode())
                    print(f"[Rendezvous] Registered: {username} at {addr[0]}:{port}")

                else:
                    peer_socket.send("ERROR: Invalid REGISTER format".encode())

    except Exception as e:
        print(f"Error handling peer {addr}: {e}")

    finally:
        print(f"[Rendezvous] Peer disconnected: {addr}")
        peer_socket.close()
        if peer_info in connected_peers:
            connected_peers.remove(peer_info)

def start_rendezvous_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 9000))
    server_socket.listen(5)

    print("[Rendezvous Server] Listening on port 9000...")

    while True:
        peer_socket, addr = server_socket.accept()
        threading.Thread(target=handle_peer, args=(peer_socket, addr), daemon=True).start()
        print("LISTENING")

if __name__ == "__main__":
    start_rendezvous_server()
