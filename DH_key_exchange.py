import secrets, hashlib, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class DH:
    def __init__(self, p:int, g:int):
        self.p = p
        self.g = g

        self.private_key = secrets.randbelow(self.p)
        self.public_key = pow(self.g, self.private_key, self.p)

        self.shared_secret = None
        self.AES_key = None
    
    def generate_shared_secret(self, their_public_key:int):
        self.shared_secret = pow(their_public_key, self.private_key, self.p)
    
    def generate_AES_key(self):
        if not self.shared_secret:
            raise SystemError("shared_secret wasn't generated!")
        
        shared_bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length()+7)//8, byteorder="big")
        self.AES_key = hashlib.sha256(shared_bytes).digest()
    
    def encrypt(self, text:bytes) -> bytes:
        if not self.AES_key:
            raise SystemError("AES_key doesn't exist!")
        
        aesgcm = AESGCM(self.AES_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, text, None)
        return nonce + ciphertext
    
    def decrypt(self, data:bytes) -> bytes:
        if not self.AES_key:
            raise SystemError("AES_key doesn't exist!")
        
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.AES_key)
        return aesgcm.decrypt(nonce, ciphertext, None)