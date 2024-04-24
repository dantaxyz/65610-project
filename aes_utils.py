from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

def make_key():
    return get_random_bytes(16)

# Implementation based off of: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes
# Encrypts a message, as well as adds an authentication tag to prevent replay attacks? 
def encrypt_message(msg, aes_key, hmac_key): 
    data = msg.encode()

    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(data)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(cipher.nonce + ciphertext).digest()

    with open("encrypted.bin", "wb") as f:
        f.write(tag)
        f.write(cipher.nonce)
        f.write(ciphertext)
    
    return tag + cipher.nonce + ciphertext # maybe concatenate these?

def decrypt_message(full_ciphertext, aes_key, hmac_key):
    
    tag = full_ciphertext[:32]
    nonce = full_ciphertext[32:40]
    ciphertext = full_ciphertext[40:]

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
    
    enc = encrypt_message("hello", aes_key, hmac_key)
    dec = decrypt_message(enc, aes_key, hmac_key)
    
    print("Encrypt returned:", enc)
    print("Decrypt returned:", dec)