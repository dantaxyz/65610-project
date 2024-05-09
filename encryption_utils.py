from aes_utils import *

def straight_enc(msg_string, aes_key):
    msg_bytes = msg_string.encode("utf-8")
    len_bytes = len(msg_bytes).to_bytes(BLOCK_LENGTH)
    return encrypt_bytes(len_bytes + msg_bytes, aes_key)

def straight_dec(ct_bytes, aes_key):
    nonce = ct_bytes[:NONCE_LENGTH]
    decrypter = get_decrypter(aes_key, nonce)

    len_bytes = decrypter.decrypt(ct_bytes[NONCE_LENGTH:NONCE_LENGTH+BLOCK_LENGTH])
    msg_len = int.from_bytes(len_bytes)

    return decrypter.decrypt(ct_bytes[NONCE_LENGTH+BLOCK_LENGTH:NONCE_LENGTH+BLOCK_LENGTH+msg_len]).decode("utf-8")