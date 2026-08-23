from oqs import KeyEncapsulation
from tinydb import TinyDB, Query
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import hashlib
import base64


def createSessionKeyPair():
    kem = KeyEncapsulation("ML-KEM-1024")
    public_key = kem.generate_keypair()
    return kem, public_key, kem.export_secret_key()

def createKeyPair(password, user):
    kem = KeyEncapsulation("ML-KEM-1024")
    pub = kem.generate_keypair()
    priv = kem.export_secret_key()

    db = TinyDB("db.json")
    query = Query()

    if db.contains(query.user == user):
        raise Exception(f"User {user} already exists")

    nonce = get_random_bytes(12)
    key = hashlib.sha256(password.encode()).digest()
    ch = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    cpriv, tag = ch.encrypt_and_digest(priv)

    db.insert({
        'user': user,
        'nonce': base64.b64encode(nonce).decode(),
        'pub': base64.b64encode(pub).decode(),
        'priv': base64.b64encode(cpriv).decode(),
        'priv_tag': base64.b64encode(tag).decode()
    })

def loadKeyPair(password, user):
    db = TinyDB("db.json")
    query = Query()
    result = db.get(query.user == user)

    if not result:
        raise Exception(f"User {user} not found, create a new key pair with \"demension --create-keypair\"")

    key = hashlib.sha256(password.encode()).digest()
    ch = ChaCha20_Poly1305.new(
        key=key,
        nonce=base64.b64decode(result['nonce'])
    )
    priv = ch.decrypt_and_verify(
        base64.b64decode(result['priv']),
        base64.b64decode(result['priv_tag'])
    )
    pub = base64.b64decode(result['pub'])

    return pub, priv

def encryptMessage(recPub, msg):
    kem = KeyEncapsulation("ML-KEM-1024")
    ct, ss = kem.encapsulate(recPub)

    nonce = get_random_bytes(12)
    key = hashlib.sha256(ss).digest()
    ch = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cht, tag = ch.encrypt_and_digest(msg.encode())

    return ct, nonce, cht, tag

def decryptMessage(priv, ct, nonce, cht, tag):
    kem = KeyEncapsulation("ML-KEM-1024")
    kem.import_secret_key(priv)
    ss = kem.decapsulate(ct)

    key = hashlib.sha256(ss).digest()
    ch = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    msg = ch.decrypt_and_verify(cht, tag)

    return msg.decode()