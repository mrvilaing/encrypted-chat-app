#!/usr/bin/env python3
"""
relay_server.py

A simple centralized chat relay server

Protocol (line-based, UTF-8):

Client -> Server:
    REGISTER <username>
    MSG <recipient> <message text...>
    LIST
    QUIT

Server -> Client:
    INFO <text>
    ERROR <text>
    USERLIST <u1> <u2> ...
    FROM <sender> <message text...>
"""

import socket
import threading

HOST = "0.0.0.0"   # listen on all interfaces
PORT = 5000        # change if you like

# username -> socket
clients = {}
clients_lock = threading.Lock()


def broadcast_info(msg: str):
    """Send an INFO message to all connected clients."""
    with clients_lock:
        for sock in clients.values():
            try:
                sock.sendall(f"INFO {msg}\n".encode("utf-8"))
            except Exception:
                # Ignore individual send errors here
                pass


def handle_client(conn: socket.socket, addr):
    """
    Handle a single client connection: registration + message loop.
    """
    username = None
    try:
        conn_file = conn.makefile("r", encoding="utf-8")

        # 1. Registration phase
        conn.sendall(b"INFO Welcome to the relay server. Please register:\n")
        conn.sendall(b"INFO Use: REGISTER <username>\n")

        line = conn_file.readline()
        if not line:
            return

        line = line.strip()
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or parts[0].upper() != "REGISTER":
            conn.sendall(b"ERROR First command must be: REGISTER <username>\n")
            return

        requested_name = parts[1].strip()
        if not requested_name:
            conn.sendall(b"ERROR Username cannot be empty.\n")
            return

        # Check if username already taken
        with clients_lock:
            if requested_name in clients:
                conn.sendall(b"ERROR Username already in use.\n")
                return
            # Register client
            clients[requested_name] = conn
            username = requested_name

        conn.sendall(f"INFO Registered as {username}\n".encode("utf-8"))
        broadcast_info(f"{username} has joined the chat.")

        # 2. Main loop: handle commands
        for line in conn_file:
            line = line.strip()
            if not line:
                continue

            parts = line.split(maxsplit=2)
            cmd = parts[0].upper()

            if cmd == "LIST":
                # Return online users
                with clients_lock:
                    names = " ".join(sorted(clients.keys()))
                conn.sendall(f"USERLIST {names}\n".encode("utf-8"))

            elif cmd == "MSG":
                if len(parts) < 3:
                    conn.sendall(b"ERROR Usage: MSG <recipient> <message>\n")
                    continue
                recipient = parts[1]
                message_text = parts[2]

                with clients_lock:
                    target_sock = clients.get(recipient)

                if target_sock is None:
                    conn.sendall(f"ERROR No such user: {recipient}\n".encode("utf-8"))
                    continue

                try:
                    print(f"[Relay] {username} -> {recipient}: {message_text}")
                    # Deliver message to recipient
                    target_sock.sendall(
                        f"FROM {username} {message_text}\n".encode("utf-8")
                    )
                    # Optional: ack
                    conn.sendall(b"INFO Message sent.\n")
                except Exception:
                    conn.sendall(b"ERROR Failed to deliver message.\n")

            elif cmd == "QUIT":
                conn.sendall(b"INFO Goodbye.\n")
                break

            else:
                conn.sendall(b"ERROR Unknown command.\n")

    except Exception as e:
        print(f"[Server] Error with client {addr}: {e}")
    finally:
        # Cleanup on disconnect
        if username is not None:
            with clients_lock:
                if clients.get(username) is conn:
                    del clients[username]
            broadcast_info(f"{username} has left the chat.")

        try:
            conn.close()
        except Exception:
            pass


def main():
    print(f"[Server] Starting relay server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("[Server] Listening for connections...")

        while True:
            conn, addr = s.accept()
            print(f"[Server] New connection from {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()

