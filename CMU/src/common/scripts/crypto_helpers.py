import monocypher
import struct

SYMMETRIC_KEY_LEN = 32
SYMMETRIC_NONCE_LEN = 24
SYMMETRIC_MAC_LEN = 16
SYMMETRIC_METADATA_LEN = 40

CC_HASH_ITERS = 16
CC_HASH_LEN = 32
CC_HASH_KEY_LEN = 32

CC_ENC_SYM_KEY_LEN = 32

CC_ENC_SYM_METADATA_LEN = 40
CC_ENC_ASYM_METADATA_LEN = 72

# these need to match crypto_wrappers.h
CC_KDF_PIN_ITERS = 750
CC_KDF_RT_ITERS = 750
CC_KDF_SUBKEY_ITERS = 32

# Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
# Provides authenticated encryption (any tampering will be detected upon decrypt)
def cc_encrypt_symmetric(plaintext, sym_key):
    assert len(sym_key) == CC_ENC_SYM_KEY_LEN
    nonce = monocypher.generate_key(SYMMETRIC_NONCE_LEN)
    mac, ct = monocypher.lock(sym_key, nonce, plaintext)
    return mac + nonce + ct

# Plaintext will be length bytes long
# Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
# Provides authenticated encryption; returns None if tampering or corruption detected
def cc_decrypt_symmetric(ciphertext, sym_key):
    assert len(sym_key) == CC_ENC_SYM_KEY_LEN
    mac = ciphertext[:16]
    nonce = ciphertext[16:40]
    ct = ciphertext[40:]
    return monocypher.unlock(sym_key, nonce, mac, ct)

def cc_hash(message):
    for _ in range(CC_HASH_ITERS):
        message = monocypher.blake2b(message)
    return message[:CC_HASH_LEN]

# Keyed hash; output CC_HASH_LENGTH bytes; expects CC_HASH_KEY_LEN byte-long key
def cc_hash_keyed(message, key):
    assert len(key) == CC_HASH_KEY_LEN

    message = monocypher.blake2b(key+message+key)
    for _ in range(CC_HASH_ITERS-1):
        message = monocypher.blake2b(message)
    return message[:CC_HASH_LEN]

def _cc_hash_keyed_raw(message, key):
    message = monocypher.blake2b(key+message+key)
    for _ in range(CC_HASH_ITERS-1):
        message = monocypher.blake2b(message)
    return message[:CC_HASH_LEN]

def _cc_hash_internal(message, key, iters, length):
    message = monocypher.blake2b(key+message+key)
    for _ in range(iters-1):
        message = monocypher.blake2b(message)
    return message[:length]

def _cc_kdf_internal(pw, depl_key):
    hash_tmp = _cc_hash_internal(depl_key[:12], b"", 4, CC_HASH_LEN)
    for _ in range(CC_KDF_PIN_ITERS):
        hash_tmp = _cc_hash_internal(hash_tmp, pw, 4, CC_HASH_LEN)
        hash_tmp = xor_bytes(hash_tmp, pw)

    hash_tmp = cc_hash(hash_tmp)
    hash_tmp = xor_bytes(hash_tmp, pw)
    return hash_tmp

# KDF for use with PIN; output CC_HASH_LENGTH bytes
def cc_kdf_pin(pin, depl_key):
    return _cc_kdf_internal(pin, depl_key)

# KDF for use with replacement token; output CC_HASH_LENGTH bytes
def cc_kdf_rt(replacement_token, depl_key):
    return _cc_kdf_internal(replacement_token, depl_key)

def _cc_kdf_subkey_internal(root_key, comp_id, pepper):
    hash_tmp = _cc_hash_internal(root_key, pepper, 4, CC_HASH_LEN)
    id_hash = _cc_hash_internal(p32(comp_id), b"", 4, CC_HASH_LEN)
    for _ in range(CC_KDF_SUBKEY_ITERS):
        hash_tmp = _cc_hash_internal(hash_tmp, id_hash, 4, CC_HASH_LEN)
        hash_tmp = xor_bytes(hash_tmp, p32(comp_id))

    hash_tmp = cc_hash(hash_tmp)
    hash_tmp = xor_bytes(hash_tmp, root_key)

    return hash_tmp

# KDF for use with AP boot root -> subkey; output CC_HASH_LENGTH bytes
def cc_kdf_ap_boot_sub_key(ap_boot_root_key, comp_id):
    return _cc_kdf_subkey_internal(ap_boot_root_key, comp_id, b"apbootsubkey----")

# KDF for use with Component boot root -> subkey; output CC_HASH_LENGTH bytes
def cc_kdf_comp_boot_sub_key(comp_boot_root_key, comp_id):
    return _cc_kdf_subkey_internal(comp_boot_root_key, comp_id, b"compbootsubkey--")

# KDF for use with Attestation root -> subkey; output CC_HASH_LENGTH bytes
def cc_kdf_att_sub_key(att_root_key, comp_id):
    return _cc_kdf_subkey_internal(att_root_key, comp_id, b"attestsubkey----")

# KDF for use with Secure send root -> subkey; output CC_HASH_LENGTH bytes
def cc_kdf_sec_send_sub_key(sec_send_root_key, comp_id):
    return _cc_kdf_subkey_internal(sec_send_root_key, comp_id, b"secsendsubkey---")

# Given byte arrays A and B, XORs the first len(B) bytes
# of A with B, and retains the rest of A as-is.
# matches the behavior of xor_bytes in crypto_wrappers.c
def xor_bytes(a, b):
    return bytes([a[i] ^ (b[i] if i < len(b) else 0) for i in range(len(a))])

def p32(x):
    return x.to_bytes(4, "little")

