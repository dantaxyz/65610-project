from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

NONCE_LENGTH = 8
BLOCK_LENGTH = 16

def make_key():
    return get_random_bytes(16)

def encrypt_bytes(msg_bytes, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CTR)
    return cipher.nonce + cipher.encrypt(msg_bytes)

def get_decrypter(aes_key, nonce):
    return AES.new(aes_key, AES.MODE_CTR, nonce=nonce)

"""

# Implementation based off of: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes
# Encrypts a message, as well as adds an authentication tag to prevent replay attacks? 
#
# TODO:
#  - add message length into encryption, so that when decoding, we can figure out which bits to decode from the audio file
def encrypt_message(msg, aes_key): 
    data = msg.encode()

    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(data)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(cipher.nonce + ciphertext).digest()

    with open("encrypted.bin", "wb") as f:
        f.write(tag)
        f.write(cipher.nonce)
        f.write(ciphertext)
    
    enc = tag + cipher.nonce + ciphertext
    return enc
    # return BitArray(enc).bin # return as bit string

def decrypt_message(full_ciphertext, aes_key):
    
    # converted_ct = BitArray(bin=full_ciphertext).bytes
    converted_ct = full_ciphertext

    tag = converted_ct[:32]
    nonce = converted_ct[32:40]
    ciphertext = converted_ct[40:]

    try:
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        tag = hmac.update(nonce + ciphertext).verify(tag)
    except ValueError:
        print("The message was modified!")
        sys.exit(1)

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    message = cipher.decrypt(ciphertext)
    print("Message:", message.decode())
    return message.decode()

if __name__=="__main__":
    aes_key = make_key()
    hmac_key = make_key()
    
    enc = encrypt_message("hello world", aes_key, hmac_key)
    dec = decrypt_message(enc, aes_key, hmac_key)
    
    print("Encrypt returned:", enc)
    print("Decrypt returned:", dec)

"""