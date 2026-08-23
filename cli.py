import sys
import threading
import connection as connection

def main():
    state = {"connected": False, "conn": None, "session": None}
    while True:
        command = input(": ")
        match command.split():
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
            case ["send", *msg]:
                if msg and state["connected"]:
                    connection.sendMessage(
                        " ".join(msg), state["conn"], state["session"]
                    )
                else:
                    print("Not connected")
            case ["exit"]:
                if state["conn"]:
                    connection.closeConnection(state["conn"])
                sys.exit(0)


if __name__ == "__main__":
    main()
