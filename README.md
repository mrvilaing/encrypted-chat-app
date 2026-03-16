# encrypted-chat-app
End-to-end encrypted chat application with relay server. Uses Ed25519 identity keys, X25519 ECDH, HKDF-SHA256, and ChaCha20-Poly1305.

READ ME
This application uses a centralized relay-based chat application with end-to-end encryption between clients. The relay server simply just forwards messages, but when a secure session is established, the relay should only output ciphertext and meta data.

- The client uses Ed25519 long term identity keys.
- It follows a Trust-On-First-Use (TOFU) for identity verification.
- X25519 ephemeral Diffie-Hellman for session key exchange.
- It uses HKDF-SHA256 to derive session keys
- ChaCha20-Poly1305 as the AEAD scheme.
- It has session-level forward secrecy.

FILES
client.py - This is the encrypted chat client.
relay_server.py - This is the centralized message relay server.

HOW TO RUN:
When you open the document "Encrypted Chat App", you should see two files. On the address bar, type "powershell" and press enter. Then a powershell window should open with the working directory sec to the project folder. You will have to do this three times.

1. First start the relay server in one terminal using:
python relay_server.py

2. Start the other two clients separately by using:
python client.py 127.0.0.1 5000

3. In the clients, register the usernames with:
REGISTER <username>

Once you load in it should generate a Ed25519 identity key for the username. As for the private key, it is stored locally in the "keys" file. You should see it appear with the other two files with both users in it.

4. Exchange Identity Keys with:
/sendpub <peer>

You would repeat it between both clients. In the case of Alice and Bob, they would exchange with each other their identity keys. For example, with Alice, she would type "/sendpub Bob" and Bob will automatically store the key and trust the key but only on the first time. Bob then does the same as Alice and Alice would store Bob's key. If Alice's or Bob's keys changes later, a TOFU warning should appear.

You can test this by going on the local "keys" file and selecting whichever user's file, and delete the PEM file with their name on it. For example, if you were to delete Alice_ed25519.pem, the next time you connect back to the server and /sendpub Bob, Bob will get a message showing that Alice's identity key has been changed. However, you would have to restart completely by deleting the keys folder.

5. To start the secure session:
/secure <peer>

Both clients enter a secure session with each other. Once they're in the secure session, on the relay terminal it will show that the handshake went through. Any messages sent then will be encrypted as shown in the relay terminal.

6. To end the secure session:
/insecure <peer>

This deletes the session key and allows the users to enter back into a non secured chat. Both users have to enter this in order to end the session.

7. Identity info:
/id

In either client, this will show the username, the public key fingerprint, along with the base64 encoded public key.

8. To quit the chat:
/quit


ps. the keys file is automatically created when you register, so you can delete it whenever you want a restart.
