import secrets
import numpy as np
from aes_utils import *

def straight_enc(msg_string, aes_key):
    msg_bytes = msg_string.encode("utf-8")
    len_bytes = len(msg_bytes).to_bytes(BLOCK_LENGTH - NONCE_LENGTH)
    return encrypt_bytes(len_bytes + msg_bytes, aes_key)

def straight_dec(ct_bytes, aes_key):
    nonce = ct_bytes[:NONCE_LENGTH]
    decrypter = get_decrypter(aes_key, nonce)

    len_bytes = decrypter.decrypt(ct_bytes[NONCE_LENGTH:BLOCK_LENGTH])
    msg_len = int.from_bytes(len_bytes)

    return decrypter.decrypt(ct_bytes[BLOCK_LENGTH:BLOCK_LENGTH+msg_len]).decode("utf-8")



# head is nonce, length and a pointer (24 bytes)
# every subsequent node is a block and a pointer (24 bytes), except the last node, which doesn't have a pointer
NODE_LENGTH = 24
def ll_enc(msg_string, aes_key, orig_lsb):
    msg_bytes = msg_string.encode("utf-8")

    num_locs = len(orig_lsb) // NODE_LENGTH
    locs, locs_set = [0], set([0])
    locs_needed = (len(msg_bytes) + BLOCK_LENGTH - 1) // BLOCK_LENGTH + 1
    while len(locs) < locs_needed:
        loc = secrets.randbelow(num_locs)
        if loc not in locs_set:
            locs_set.add(loc)
            locs.append(loc)
    
    to_encrypt = b""
    for i, loc in enumerate(locs[1:]):
        to_encrypt += loc.to_bytes(NODE_LENGTH - BLOCK_LENGTH)
        to_encrypt += msg_bytes[i*BLOCK_LENGTH : i*BLOCK_LENGTH + BLOCK_LENGTH]
    to_encrypt = len(to_encrypt).to_bytes(BLOCK_LENGTH - NONCE_LENGTH) + to_encrypt
    encrypted_data = encrypt_bytes(to_encrypt, aes_key)

    encrypted_arr = np.frombuffer(encrypted_data, dtype=np.uint8)
    modified_lsb_arr = np.frombuffer(orig_lsb, dtype=np.uint8).copy()
    for i, loc in enumerate(locs[:-1]):
        modified_lsb_arr[loc*NODE_LENGTH : loc*NODE_LENGTH + NODE_LENGTH] = encrypted_arr[i*NODE_LENGTH : i*NODE_LENGTH + NODE_LENGTH]
    modified_lsb_arr[locs[-1]*NODE_LENGTH : locs[-1]*NODE_LENGTH + len(encrypted_arr) - (len(locs) - 1)*NODE_LENGTH] = encrypted_arr[(len(locs) - 1)*NODE_LENGTH :]
    
    return modified_lsb_arr.tobytes()

def ll_dec(ct_bytes, aes_key):
    nonce = ct_bytes[:NONCE_LENGTH]
    decrypter = get_decrypter(aes_key, nonce)
    encrypted_len = int.from_bytes(decrypter.decrypt(ct_bytes[NONCE_LENGTH:BLOCK_LENGTH]))
    
    msg_bytes = b""
    last_loc = 0
    while len(msg_bytes) < encrypted_len:
        next_loc_bytes = decrypter.decrypt(ct_bytes[last_loc*NODE_LENGTH + BLOCK_LENGTH : last_loc*NODE_LENGTH + NODE_LENGTH])
        next_loc = int.from_bytes(next_loc_bytes)
        encrypted_len -= NODE_LENGTH - BLOCK_LENGTH
        msg_bytes += decrypter.decrypt(ct_bytes[next_loc*NODE_LENGTH : next_loc*NODE_LENGTH + BLOCK_LENGTH])
        last_loc = next_loc
    
    return msg_bytes[:encrypted_len].decode("utf-8")