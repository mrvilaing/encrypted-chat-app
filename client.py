#!/usr/bin/env python3
"""
client.py
End-to-end encrypted chat client built on top of a centralized relay server.

"""
# Standard library imports
import socket
import threading
import sys
import os
import hashlib
import base64
import json
import secrets

# Cryptography primitives
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# Storage layout (identity keys + TOFU peer files
KEYS_DIR = "keys"

def user_dir(username: str) -> str:
    # Per user directory under KEYS_DIR
    return os.path.join(KEYS_DIR, safe_name(username).lower())

def known_peers_path(username: str) -> str:
    # Path to TOFU peer file for a given local user
    # Stores peer identity public keys the first time it is seen
    return os.path.join(user_dir(username), "known_peers.json")

# Secure handshake state 
# In memory secure session state
# pending_hs: initiator waiting for HS2
# sessions: established session keys
# nonces_seen: basic replay detection (nonce reuse)
pending_hs = {}   # peer -> our X25519PrivateKey (waiting for HS2)
sessions = {}     # peer -> session_key bytes (32 bytes) 
nonces_seen = {}   # peer -> set of nonce base64 strings (replay detection)

def b64e(b: bytes) -> str:
    # Bytes -> base64(ascii str)
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    # Base64(ascii str) -> bytes
    return base64.b64decode(s.encode("ascii"))

def hs_transcript(tag: str, sender: str, receiver: str, eph_pub: bytes) -> bytes:
    # Binds protocol version, message type, identity and the ephemeral public key
    # Create the exact bytes that are signed/verified for HS1 and HS2
    return f"CHATv1|{tag}|{sender}|{receiver}|".encode("utf-8") + eph_pub

def derive_session_key(shared: bytes, a: str, b: str) -> bytes:
    # Derive a 32-byte session key from the X25519 shared secret using HKDF SHA-256
    # stable ordering so both sides match
    x, y = sorted([a, b])
    salt = hashlib.sha256(f"{x}|{y}".encode("utf-8")).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"CHATv1 session").derive(shared)

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> str:
    # Encrypt plaintext with ChaCha20-Poly1305
    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12) 
    ct = aead.encrypt(nonce, plaintext, aad)
    return f"{b64e(nonce)} {b64e(ct)}"

def aead_decrypt(key: bytes, nonce_b64: str, ct_b64: str, aad: bytes) -> bytes:
    # Decrypt and authenticate ciphertext with ChaCha20-Poly1305
    nonce = b64d(nonce_b64)
    ct = b64d(ct_b64)
    if len(nonce) != 12:
        raise ValueError("bad nonce length")
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct, aad)

def msg_aad(sender: str, receiver: str) -> bytes:
    # Bind ciphertext to who it's from/to (prevents swapping)
    return f"CHATv1|MSG|{sender}|{receiver}".encode("utf-8")

def load_known_peers_for(username: str) -> dict:
    # Load known peers map from disk (TOFU file)
    d = user_dir(username)
    ensure_dir(d)
    path = known_peers_path(username)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_known_peers_for(username: str, peers: dict):
    # Save known peers map to disk (TOFU file)
    d = user_dir(username)
    ensure_dir(d)
    path = known_peers_path(username)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(peers, f, indent=2)

def ensure_dir(path: str):
    # Creates a directory if it doesn't already exist
    os.makedirs(path, exist_ok=True)

def safe_name(name: str) -> str:
    # Keeps usernames simple for filesystem usage
    return "".join(c for c in name if c.isalnum() or c in ("-", "_"))

def key_path(username: str) -> str:
    # Path to the user's Ed25519 private key PEM file 
    d = user_dir(username)
    ensure_dir(d)
    return os.path.join(d, f"{safe_name(username)}_ed25519.pem")

def fingerprint(pub_bytes: bytes) -> str:
    # Display first 16 hex characters of SHA-256)
    return hashlib.sha256(pub_bytes).hexdigest()[:16]  

def load_or_create_identity(username: str):
    # Load Ed25519 identity key from file if it exists
    path = key_path(username)

    if os.path.exists(path):
        with open(path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    else:
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)

    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub

def recv_loop(sock: socket.socket, peers: dict, state: dict):
    # Background receive loop
    # Handles TOFU identity key learning, secure handshake messages, and encrypted application messages
    conn_file = sock.makefile("r", encoding="utf-8")
    for line in conn_file:
        line = line.rstrip("\n")

        # Relay protocol delivers messages as: FROM <sender> <payload>
        if line.startswith("FROM "):
            parts = line.split(" ", 2)  # FROM <sender> <payload>
            if len(parts) < 3:
                print(f"\n{line}")
                print("> ", end="", flush=True)
                continue

            sender = parts[1]
            payload = parts[2].strip()

            # Learn peer identity pubkey (TOFU)
            if payload.startswith("PUBKEY "):
                b64 = payload.split(" ", 1)[1].strip()
                try:
                    pub_bytes = base64.b64decode(b64.encode("ascii"))
                except Exception:
                    print(f"\n[TOFU] Invalid PUBKEY from {sender}")
                    print("> ", end="", flush=True)
                    continue

                fp = fingerprint(pub_bytes)

                if not state["username"]:
                    print("\n[TOFU] REGISTER first.")
                    print("> ", end="", flush=True)
                    continue

                if sender not in peers:
                    # Stores peer key if first time seeing it (TOFU)
                    peers[sender] = {"pub_b64": b64, "fp": fp}
                    save_known_peers_for(state["username"], peers)
                    print(f"\n[TOFU] Learned {sender} identity key. fingerprint={fp}")

                else:
                    # Detects change from key known and warns
                    if peers[sender]["pub_b64"] != b64:
                        print(f"\n[WARNING] {sender} identity key changed!")
                        print(f"          old fp={peers[sender]['fp']}")
                        print(f"          new fp={fp}")
                        print("          Possible MITM or key reset.")
                    else:
                        print(f"\n[TOFU] {sender} key already known. fingerprint={fp}")

                print("> ", end="", flush=True)
                continue

            # Handshake responder: receive HS1, verify, reply HS2
            if payload.startswith("HS1 "):
                my_username = state["username"]
                my_priv = state["priv"]

                if not my_username or not my_priv:
                    print("\n[SECURE] You must REGISTER first (local identity not loaded).")
                    print("> ", end="", flush=True)
                    continue
                if sender not in peers:
                    print(f"\n[SECURE] HS1 from unknown peer {sender}")
                    print("> ", end="", flush=True)
                    continue

                # Parse: HS1 <eph_pub_64> <sig_b64>
                try:
                    _, eph_b64, sig_b64 = payload.split(" ", 2)
                    eph_pub_peer = b64d(eph_b64)
                    if len(eph_pub_peer) != 32:
                        print(f"\n[SECURE] Bad ephemeral key length from {sender}")
                        print("> ", end="", flush=True)
                        continue
                    sig_peer = b64d(sig_b64)
                except Exception:
                    print(f"\n[SECURE] Malformed HS1 from {sender}")
                    print("> ", end="", flush=True)
                    continue

                # Verify peer signature using TOFU stored identity key
                peer_pub_bytes = base64.b64decode(peers[sender]["pub_b64"].encode("ascii"))
                peer_pub = Ed25519PublicKey.from_public_bytes(peer_pub_bytes)
                try:
                    peer_pub.verify(
                        sig_peer,
                        hs_transcript("HS1", sender, my_username, eph_pub_peer)
                    )
                except Exception:
                    print(f"\n[SECURE] Invalid HS1 signature from {sender}")
                    print("> ", end="", flush=True)
                    continue

                # Create the ephemeral keypair and derive session key
                eph_priv = X25519PrivateKey.generate()
                eph_pub_me = eph_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                shared = eph_priv.exchange(
                    X25519PublicKey.from_public_bytes(eph_pub_peer)
                )
                sessions[sender] = derive_session_key(shared, my_username, sender)
                # Signs HS2 transcript and send back
                sig2 = my_priv.sign(
                    hs_transcript("HS2", my_username, sender, eph_pub_me)
                )

                sock.sendall(
                    f"MSG {sender} HS2 {b64e(eph_pub_me)} {b64e(sig2)}\n".encode("utf-8")
                )

                print(f"\n[SECURE] Session established with {sender}")
                print("> ", end="", flush=True)
                continue

            # Handshake initiator: receive HS2, verify, finish handshake
            if payload.startswith("HS2 "):
                my_username = state["username"]
                my_priv = state["priv"]
                if not my_username or not my_priv:
                    print("\n[SECURE] You must REGISTER first (local identity not loaded).")
                    print("> ", end="", flush=True)
                    continue
                if sender not in pending_hs:
                    print(f"\n[SECURE] Unexpected HS2 from {sender}")
                    print("> ", end="", flush=True)
                    continue

                # Parse: HS2 <eph_pub_b64> <sig_b64>
                try:
                    _, eph_b64, sig_b64 = payload.split(" ", 2)
                    eph_pub_peer = b64d(eph_b64)
                    if len(eph_pub_peer) != 32:
                        print(f"\n[SECURE] Bad ephemeral key length from {sender}")
                        print("> ", end="", flush=True)
                        continue
                    sig_peer = b64d(sig_b64)
                except Exception:
                    print(f"\n[SECURE] Malformed HS2 from {sender}")
                    print("> ", end="", flush=True)
                    continue

                # Verify peer signature over HS2 transcript
                peer_pub_bytes = base64.b64decode(peers[sender]["pub_b64"].encode("ascii"))
                peer_pub = Ed25519PublicKey.from_public_bytes(peer_pub_bytes)
                try:
                    peer_pub.verify(
                        sig_peer,
                        hs_transcript("HS2", sender, my_username, eph_pub_peer)
                    )
                except Exception:
                    print(f"\n[SECURE] Invalid HS2 signature from {sender}")
                    print("> ", end="", flush=True)
                    continue

                # Finish ECDH with our stored eph priv
                eph_priv = pending_hs.pop(sender)
                shared = eph_priv.exchange(
                    X25519PublicKey.from_public_bytes(eph_pub_peer)
                )
                sessions[sender] = derive_session_key(shared, my_username, sender)

                print(f"\n[SECURE] Session established with {sender}")
                print("> ", end="", flush=True)
                continue

            # Encrypted application message handler
            if payload.startswith("ENC "):
                if sender not in sessions:
                    print(f"\n[SECURE] Received encrypted msg from {sender}, but no session exists.")
                    print("> ", end="", flush=True)
                    continue
                if not state["username"]:
                    print("\n[SECURE] REGISTER first.")
                    print("> ", end="", flush=True)
                    continue

                try:
                    _, nonce_b64, ct_b64 = payload.split(" ", 2)
                except Exception:
                    print(f"\n[SECURE] Malformed ENC from {sender}")
                    print("> ", end="", flush=True)
                    continue

                # Replay protection: detects if nonce is reused and rejects
                nh = nonce_b64 
                seen = nonces_seen.setdefault(sender, set())
                if nh in seen:
                    print(f"\n[SECURE] Replay detected from {sender} (nonce reused)")
                    print("> ", end="", flush=True)
                    continue
                seen.add(nh)

                try:
                    aad = msg_aad(sender, state["username"])
                    pt = aead_decrypt(sessions[sender], nonce_b64, ct_b64, aad)
                    print(f"\n{sender} (secure): {pt.decode('utf-8', errors='replace')}")
                except Exception:
                    print(f"\n[SECURE] Failed to decrypt/authenticate message from {sender}")
                print("> ", end="", flush=True)
                continue

            # Default fall back
            print(f"\n{line}")
            print("> ", end="", flush=True)
            continue

        print(f"\n{line}")
        print("> ", end="", flush=True)
# Sender loop with CLI commands, secure session control, send path
def send_loop(sock: socket.socket, peers: dict, state: dict):
    try:
        my_username = None
        my_pub = None
        my_priv = None

        while True:
            msg = input("> ")
            # Quit
            if msg.strip().lower() in {"/quit", "quit", "exit"}:
                sock.sendall(b"QUIT\n")
                break
            # ID
            if msg.strip().lower() == "/id":
                if not my_pub:
                    print("[System] You must REGISTER first")
                else:
                    pub_b64 = base64.b64encode(my_pub).decode("ascii")
                    print(f"[ID] username={my_username} fingerprint={fingerprint(my_pub)}")
                    print(f"[ID] pubkey(base64)={pub_b64}")
                continue
            # Send public key to peer
            if msg.strip().lower().startswith("/sendpub "):
                if not my_pub or not my_username:
                    print("[System] You must REGISTER first")
                    continue
                parts = msg.strip().split(maxsplit=1)
                if len(parts) != 2:
                    print("[System] Usage: /sendpub <recipient>")
                    continue
                recipient = parts[1].strip()
                pub_b64 = base64.b64encode(my_pub).decode("ascii")
                sock.sendall(
                    f"MSG {recipient} PUBKEY {pub_b64}\n".encode("utf-8")
                )
                print(f"[ID] Sent identity pubkey to {recipient}")
                continue
            # Start secure session: sends HS1
            if msg.strip().lower().startswith("/secure "):
                if not my_priv or not my_username:
                    print("[System] You must REGISTER first")
                    continue
                parts = msg.strip().split(maxsplit=1)
                if len(parts) != 2:
                    print("[System] Usage: /secure <peer>")
                    continue
                peer = parts[1].strip()
                # Must have learned peer identity key via TOFU first
                if peer not in peers:
                    print("[System] Peer identity unknown. Use /sendpub first and TOFU-learn it.")
                    continue
                eph_priv = X25519PrivateKey.generate()
                eph_pub = eph_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                sig = my_priv.sign(hs_transcript("HS1", my_username, peer, eph_pub))
                pending_hs[peer] = eph_priv
                sock.sendall(f"MSG {peer} HS1 {b64e(eph_pub)} {b64e(sig)}\n".encode("utf-8"))
                print(f"[SECURE] Sent HS1 to {peer}. Waiting for HS2...")
                continue
            # Leaves secure session and reverts to plaintext
            if msg.strip().lower().startswith("/insecure "):
                parts = msg.strip().split(maxsplit=1)
                if len(parts) != 2:
                    print("[System] Usage: /insecure <peer>")
                    continue

                peer = parts[1].strip()
                if peer in sessions:
                    del sessions[peer]
                    nonces_seen.pop(peer, None)
                    pending_hs.pop(peer, None)
                    print(f"[SECURE] Session with {peer} terminated. Back to plaintext.")
                else:
                    print(f"[SECURE] No active secure session with {peer}.")
                continue

            # If secure session is established, encrypts MSG
            parts2 = msg.strip().split(" ", 2)
            if len(parts2) >= 3 and parts2[0].upper() == "MSG":
                peer = parts2[1]
                body = parts2[2]

                if peer in sessions:
                    key = sessions[peer]
                    aad = msg_aad(my_username, peer)
                    enc = aead_encrypt(key, body.encode("utf-8"), aad)
                    sock.sendall(f"MSG {peer} ENC {enc}\n".encode("utf-8"))
                    print(f"[SECURE] sent encrypted message to {peer}")
                    continue
                else:
                    # No secure session: fall back to plaintext relay message
                    sock.sendall((msg.strip() + "\n").encode("utf-8"))
                    continue

            # Handles: load identity and load TOFU files
            parts = msg.strip().split()
            if len(parts) == 2 and parts[0].upper() == "REGISTER":
                username = parts[1]
                priv, pub = load_or_create_identity(username)
                my_username = username
                my_pub = pub
                my_priv = priv

                # Share identity into receiver thread through state dict
                state["username"] = username
                state["priv"] = priv

                # Load per-user TOFU peers
                peers.clear()
                peers.update(load_known_peers_for(username))

                print(
                    f"[ID] Loaded identity for {username}. "
                    f"fingerprint={fingerprint(pub)}"
                )
            msg_line = msg.strip() + "\n"
            sock.sendall(msg_line.encode("utf-8"))
            continue
    except (EOFError, KeyboardInterrupt):
        print("\n[System] Exiting...")
        try:
            sock.sendall(b"QUIT\n")
        except Exception:
            pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

# Connect socket and start threads
def main():
    if len(sys.argv) != 3:
        print("Usage: python client.py <server_host> <server_port>")
        sys.exit(1)

    server_host = sys.argv[1]
    server_port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[System] Connecting to {server_host}:{server_port} ...")
    sock.connect((server_host, server_port))
    print("[System] Connected.")

    peers = {}

    state = {
        "username": None,
        "priv": None
    }

    t = threading.Thread(target=recv_loop, args=(sock, peers, state), daemon=True)
    t.start()
    send_loop(sock, peers, state)

if __name__ == "__main__":
    main()

