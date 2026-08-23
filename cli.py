import sys
import threading
import connection as connection
import kyber
import base64
import json

def main():
    state = {"connected": False, "conn": None, "session": None}
    while True:
        command = input(": ")
        match command.split():
            case ["create-keypair", user, password]:
                try:
                    kyber.createKeyPair(password, user)
                    print(f"Key pair created for {user}")
                except Exception as e:
                    print(f"Error: {e}")
            case ["encrypt", user, *message_parts] if message_parts:
                try:
                    public_key = kyber.loadPublicKey(user)
                    ct, nonce, ciphertext, tag = kyber.encryptMessage(
                        public_key, " ".join(message_parts)
                    )
                    print(json.dumps({
                        "ct": base64.b64encode(ct).decode(),
                        "nonce": base64.b64encode(nonce).decode(),
                        "data": base64.b64encode(ciphertext).decode(),
                        "tag": base64.b64encode(tag).decode(),
                    }, separators=(",", ":")))
                except Exception as e:
                    print(f"Error: {e}")
            case ["decrypt", user, password, packet]:
                try:
                    _, private_key = kyber.loadKeyPair(password, user)
                    encrypted = json.loads(packet)
                    message = kyber.decryptMessage(
                        private_key,
                        base64.b64decode(encrypted["ct"]),
                        base64.b64decode(encrypted["nonce"]),
                        base64.b64decode(encrypted["data"]),
                        base64.b64decode(encrypted["tag"]),
                    )
                    print(message)
                except Exception as e:
                    print(f"Error: {e}")
            case ["start", ip, port]:
                sock = connection.createSocket()
                thread = threading.Thread(
                    target=connection.listener,
                    args=(sock, True, state, ip, port),
                    daemon=True,
                )
                thread.start()
                print(f"Listening on {ip}:{port}")
            case ["connect", ip, port]:
                sock = connection.createSocket()
                conn = connection.connectToSocket(sock, ip, port)
                if conn:
                    state["conn"] = conn
                    state["session"] = connection.establishSession(conn)
                    state["connected"] = True
                    print(f"Connected to {ip}:{port}")
                    threading.Thread(
                        target=connection.listener,
                        args=(conn, False, state),
                        daemon=True,
                    ).start()
            case ["send", *message_parts] if message_parts:
                if state["connected"]:
                    connection.sendMessage(
                        " ".join(message_parts), state["conn"], state["session"]
                    )
                else:
                    print("Not connected")
            case ["exit"]:
                if state["conn"]:
                    connection.closeConnection(state["conn"])
                sys.exit(0)


if __name__ == "__main__":
    main()
