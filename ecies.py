import os, sys, struct
from cryptography.hazmat.primitives import hashes, hmac, serialization, keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

"""
encrypt ()
params: remote public key object, plaintext (to be encrypted)
returns: ciphertext (local public key, ciphertext, mac tag)
"""
def ecies_encrypt (remote_public_key, plaintext):
    # curve (supports 256, 384 and 512 but currently hardcoded to 256)
    # hash algorithm (css supports sha-256-128)
    curve = ec.SECP256R1()
    hash_algorithm = hashes.SHA256()

    # derived constants from variables specified above
    encryption_key_length = len(plaintext)
    field_length = int(curve.key_size / 8)
    hash_length = hash_algorithm.digest_size
    mac_length =  int(hash_length / 2)

    # generate private key from specified elliptical curve
    # derive key using diffie hellman key exchange
    prv_key = ec.generate_private_key(curve)
    drv_key = X963KDF(hash_algorithm, encryption_key_length+hash_length, None).derive(prv_key.exchange(ec.ECDH(), remote_public_key))

    # derived mac and encryption key and encrypt the ciphertext (xor) 
    mac_key, enc_key = drv_key[:hash_length], drv_key[hash_length:]
    enc_plaintext = bytes(a ^ b for (a, b) in zip (enc_key, plaintext))
    mac = hmac.HMAC(mac_key, hash_algorithm)
    mac.update(enc_plaintext)
    mac_digest = mac.finalize()[:mac_length]

    # return the ciphertext
    return (prv_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint) + enc_plaintext + mac_digest)


"""
decrypt ()
params: keyblob, local private key object
returns: decrypted plaintext
"""
def ecies_decrypt (keyblob, prv_key):
    # curve (supports 256, 384 and 512 but currently hardcoded to 256)
    # hash algorithm (css supports sha-256-128)
    curve = ec.SECP256R1()
    hash_algorithm = hashes.SHA256()

    # derived constants from the variables above
    field_length = int(curve.key_size / 8)
    hash_length = hash_algorithm.digest_size
    mac_length =  int(hash_length / 2)
    
    # check whether the public key is compressed or not
    if keyblob[0] == 4:
        point_length = 2 * field_length + 1
    else:
        raise TypeError("Does not support compressed keys")

    # derive the remote public key from the keyblob
    remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, keyblob[:point_length])
    ciphertext =  keyblob[point_length:len(keyblob) - mac_length]
    digest = keyblob[-mac_length:]
    encryption_key_length = len(ciphertext)
    
    # derive the derived key, mac and encryption key to decrypt the plaintext
    drv_key = X963KDF(hash_algorithm, encryption_key_length+hash_length, None).derive(prv_key.exchange(ec.ECDH(), remote_public_key))
    mac_key, enc_key = drv_key[:hash_length], drv_key[hash_length:]
    plaintext = bytes(a ^ b for (a, b) in zip (enc_key, ciphertext))

    mac = hmac.HMAC(mac_key, hash_algorithm)
    mac.update(ciphertext)
    digest2 = mac.finalize()[:mac_length]

    # assert the digest from the keyblob is equal to the digest from the hmac
    assert digest == digest2

    # returns the plaintext
    return plaintext
