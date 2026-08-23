import base64
import json
import socket
import struct
import kyber

_HEADER = struct.Struct("!I")


def createSocket():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def createAndListen(sock, host="0.0.0.0", port=5000):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    conn, _ = sock.accept()
    sock.close()
    return conn


def connectToSocket(sock, ip, port):
    try:
        sock.connect((ip, int(port)))
        return sock
    except Exception as e:
        print(e.__class__)
        return None


def _recv_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def _send_packet(conn, packet):
    payload = json.dumps(packet, separators=(",", ":")).encode()
    conn.sendall(_HEADER.pack(len(payload)) + payload)


def _recv_packet(conn):
    header = _recv_exact(conn, _HEADER.size)
    if header is None:
        return None
    size = _HEADER.unpack(header)[0]
    if size > 1024 * 1024:
        raise ValueError("Packet is too large")
    payload = _recv_exact(conn, size)
    return json.loads(payload) if payload else None


def establishSession(conn, is_server=False):
    kem, public_key, secret_key = kyber.createSessionKeyPair()
    local = {"type": "hello", "pub": base64.b64encode(public_key).decode()}
    if is_server:
        peer = _recv_packet(conn)
        _send_packet(conn, local)
    else:
        _send_packet(conn, local)
        peer = _recv_packet(conn)
    if not peer or peer.get("type") != "hello":
        raise ValueError("Invalid handshake")
    return {"kem": kem, "secret_key": secret_key,
            "peer_pub": base64.b64decode(peer["pub"])}


def sendMessage(msg, conn, session=None):
    try:
        if session is None:
            raise ValueError("Encrypted session is not established")
        ct, nonce, ciphertext, tag = kyber.encryptMessage(session["peer_pub"], msg)
        _send_packet(conn, {
            "type": "message",
            "ct": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
        })
    except Exception as e:
        print(e.__class__)


def recieveMessage(conn, session):

    try:
        packet = _recv_packet(conn)
        if packet is None:
            return None
        if packet.get("type") != "message":
            raise ValueError("Invalid message packet")
        return kyber.decryptMessage(
            session["secret_key"],
            base64.b64decode(packet["ct"]),
            base64.b64decode(packet["nonce"]),
            base64.b64decode(packet["data"]),
            base64.b64decode(packet["tag"]),
        )
    except Exception as e:
        print(e.__class__)
        return None

def closeConnection(conn):
    try:
        conn.close()
    except Exception as e:
        print(e.__class__)

def listener(sock, is_server=False, state=None, host="0.0.0.0", port=5000):
    conn = createAndListen(sock, host, int(port)) if is_server else sock
    try:
        session = (state.get("session") if state and state.get("session")
                   else establishSession(conn, is_server=is_server))
        if state is not None:
            state["conn"] = conn
            state["session"] = session
            state["connected"] = True
        while True:
            msg = recieveMessage(conn, session)
            if msg is None:
                break
            print(f"\npeer: {msg}")
    except Exception as e:
        print(e.__class__)
    finally:
        if state is not None:
            state["connected"] = False
        closeConnection(conn)

    