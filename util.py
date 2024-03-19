import datetime
import os
import sqlite3
import threading
import uuid

import fastapi
import pyaes
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from jwcrypto import jwk, jwt
from pydantic import BaseModel

mutex = threading.Lock()

DB_FILE = ""
NEXT_KEYS = []  # list of keys that will be used for the next requests
threads = []  # list of threads that are generating keys


class SQLConnectionHandler:
    """
    Context manager for handling SQL connections
    Just a wrapper around sqlite3.connect, saving a few lines of code every time we need to use a connection
    """

    def __init__(self, path: str):
        self.path = path

    def __enter__(self) -> sqlite3.Connection:
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row  # return rows as dictionaries instead of tuples
        self.cursor: sqlite3.Cursor = self.connection.cursor()
        self.execute = self.connection.execute  # for convenience
        self.commit = self.connection.commit  # also for convenience
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connection.close()  # close the connection when we're done with it


class AuthRequest(BaseModel):
    """
    The authentication request object for /auth
    format:
    {
        "username": "example_user",
        "password": "example_password"
    }
    """
    username: str
    password: str


class RegistrationRequest(BaseModel):
    username: str
    email: str


def __init() -> None:
    global DB_FILE, NEXT_KEYS
    """
    Initialize the database and generate the keys. Should only be called once at the start of the program
    :return: None
    """
    load_dotenv()
    DB_FILE = os.getenv("DB_FILE")

    with SQLConnectionHandler(DB_FILE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, "
                   "key BLOB, exp INTEGER NOT NULL DEFAULT 0);")
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );""")
        db.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
    );""")
        db.commit()

    for i in range(5 + 2):  # generate 5 keys to start with, and 2 more used right after this
        NEXT_KEYS.append(rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        ))

    # Extra 2 keys are used here
    generate_jwt_pair(AuthRequest(username="expired_user", password="expired_password"), True)
    generate_jwt_pair(AuthRequest(username="userABC", password="password123"), False)


def generate_jwk(pubkey: rsa.RSAPublicKey, kid: str) -> jwk.JWK:
    """
    Generate a new JWK and add it to the list of valid keys
    :param pubkey: The RSA public key
    :param kid: Key ID to use for the new key
    :return: The created JWK
    """
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk_key = jwk.JWK.from_pem(pem)
    jwk_key.kid = kid  # actually set the kid
    return jwk_key


def generate_jwt_pair(request: AuthRequest, expired: bool) -> tuple[jwk.JWK, jwt.JWT]:
    """
    Generate a new JWK and JWT pair
    :param request: The request object containing the username and password
    :param expired: Whether the key should be expired
    :return: The created JWK and JWT
    """

    # Python is SLOW, so to actually trigger the 10/s rate limit, we have to do this
    # Generating the private key is the slowest part of this function, taking > 0.1s
    # What we do instead, is having a queue of about 5 keys, and when we run out, we generate 5 more concurrently

    with mutex:
        if len(NEXT_KEYS) == 0 and len(threads):  # we have to do this to avoid a race condition
            threads[0].join()  # wait for the first thread to finish
            threads.pop(0)  # remove the first thread from the list
        privkey = NEXT_KEYS.pop(0)  # NEXT_KEYS is now guaranteed to have at least 1 key, enforced by mutex
        if len(NEXT_KEYS) == 1:  # if we're running out of keys, generate some more
            for i in range(5):  # generate 5 new keys. NEXT_KEYS might not be empty, but that's fine
                generate_key_thread = threading.Thread(
                    # lambda here to avoid a pointless func definition elsewhere
                    target=lambda: NEXT_KEYS.append(rsa.generate_private_key(public_exponent=65537, key_size=2048))
                )
                generate_key_thread.start()
                threads.append(generate_key_thread)

    # End threading weirdness

    pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    if expired:  # generate expiry timestamp
        expiry = datetime.datetime.now().timestamp() + -30*60
    else:
        expiry = datetime.datetime.now().timestamp() + 60*60

    kid = save_key(pem, int(expiry))  # save the key to the database
    jwk_key = generate_jwk(privkey.public_key(), kid)  # generate a new key, add to the list

    header = {
        "alg": "RS256",
        "kid": kid
    }
    claims = {
        "sub": request.username,
        "kid": kid,
        # I can just add offset to change expiry instead of playing with timedeltas
        "exp": expiry
    }
    token = jwt.JWT(header=header, claims=claims)
    jwk_privkey = jwk.JWK.from_pem(pem)
    token.make_signed_token(jwk_privkey)
    return jwk_key, token


def save_key(key: bytes, expiry: int) -> str:
    """
    Saves the private key to the database
    :param key: The private key to save
    :param expiry: The expiry timestamp
    :return: the key ID of the saved key (The primary key for that row)
    """
    aes_key = os.getenv("NOT_MY_KEY")
    aes = pyaes.AESModeOfOperationCTR(aes_key.encode("utf-8"))
    key = aes.encrypt(key)
    with SQLConnectionHandler(DB_FILE) as db:
        db.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, expiry))
        db.commit()
        # have to do this to get the kid since it's autoincrement
        kid = db.execute("SELECT kid FROM keys WHERE key = ?", (key,)).fetchone()["kid"]

    return str(kid)  # the grader expects a string, so I typecast it here instead of everywhere else


def get_jwks() -> list[jwk.JWK]:
    """
    :return: The list of valid keys
    """
    with SQLConnectionHandler(DB_FILE) as db:
        keys = db.execute("SELECT kid, key FROM keys").fetchall()

    jwks = []
    for i in keys:
        aes_key = os.getenv("NOT_MY_KEY")
        aes = pyaes.AESModeOfOperationCTR(aes_key)
        i["key"] = aes.decrypt(i["key"])
        # We have to regenerate the JWK from the private key
        privkey = serialization.load_pem_private_key(i["kid"], password=None)
        jwks.append(generate_jwk(privkey.public_key(), str(i["key"])))

    return jwks


def register_user(request: RegistrationRequest):
    password = uuid.uuid4()
    ph = PasswordHasher()
    hashed = ph.hash(str(password))

    db = sqlite3.connect(DB_FILE)
    with SQLConnectionHandler(DB_FILE) as db:
        print(request.email)
        db.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                   (request.username, hashed, request.email))
        db.commit()

    return str(password)


def authenticate(request: fastapi.Request, auth_request: AuthRequest):
    with SQLConnectionHandler(DB_FILE) as db:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        userid = db.execute("SELECT id FROM users WHERE username = ?",
                            (auth_request.username,)).fetchone()["id"]
        db.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                   (request.client.host, timestamp, userid))
        db.commit()


__init()  # initialize the database and generate keys
