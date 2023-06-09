import os, binascii
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

"""
constants
"""
curve = ec.SECP384R1()
plaintext = b'a secret message'
encryption_key_length = 32
random_number = os.urandom(16)
shared_info_1 = b'Peter and Harry'
shared_info_2 = b'Harry and Peter'
hash_algorithm = hashes.SHA256()
field_length = int(curve.key_size / 8)
hash_length = hash_algorithm.digest_size

def private_key_generate (curve):
    return ec.generate_private_key(curve)

def shared_key_generate (private_key, public_key):
    return private_key.exchange(ec.ECDH(), public_key)

def derived_key_generate (shared_key, shared_info_1, encryption_key_length, hash_length):
    derived_key = HKDF(algorithm=hash_algorithm, length=encryption_key_length+hash_length, salt=None, info=shared_info_1).derive(shared_key)
    return (derived_key, derived_key[:encryption_key_length], derived_key[encryption_key_length:])

def encrypt_plaintext (encryption_key, plaintext, random_number):
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(random_number)).encryptor()
    return (encryptor.update(plaintext) + encryptor.finalize())

def decrypt_ciphertext (encryption_key, ciphertext, random_number):
    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(random_number)).decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize())

def mac (mac_key, ciphertext, shared_info_2):
    mac = hmac.HMAC(mac_key, hash_algorithm)
    mac.update(ciphertext + shared_info_2)
    return (mac, mac.finalize())

def encapsulation (private_key, ciphertext, digest):
    return private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint) + ciphertext + digest

def point_type_check (code, field_length):
    if code == 2 or code == 3:
        return field_length + 1 # compressed (the x-coordinate is a single bit)
    elif code == 4:
        return 2 * field_length + 1 # uncompressed
    else:
        raise TypeError('Invalid Public Key Format')
    
def public_key_compute (curve, point_length):
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, output[:point_length])

def output_decomposition (output, point_length, hash_length):
    return (output[point_length:len(output) - hash_length], output[-hash_length:])

def verify_encryption_decryption (digest, derived_digest, plaintext, derived_plaintext):
    assert digest == derived_digest
    assert plaintext == derived_plaintext

alice_private_key, bob_private_key = private_key_generate(curve), private_key_generate(curve)

shared_key = shared_key_generate(alice_private_key, bob_private_key.public_key())

derived_key, encryption_key, mac_key = derived_key_generate(shared_key, shared_info_1, encryption_key_length, hash_length)

encrypted_plaintext = encrypt_plaintext(encryption_key, plaintext, random_number)
message_authentication_code, digest = mac(mac_key, encrypted_plaintext, shared_info_2)

output = encapsulation(alice_private_key, encrypted_plaintext, digest)

point_length = point_type_check(output[0], field_length) 

alice_public_key = public_key_compute(curve, point_length) # alice_public_key = alice_private_key.public_key()
derived_encrypted_plaintext, derived_digest = output_decomposition(output, point_length, hash_length) # derived_encrypted_plaintext = encrypted_plaintext

derived_shared_key = shared_key_generate(bob_private_key, alice_public_key) # derived_shared_key = shared_key

decrypted_ciphertext = decrypt_ciphertext(encryption_key, derived_encrypted_plaintext, random_number)

derived_maessage_authentication_code = mac(mac_key, encrypted_plaintext, shared_info_2)

verify_encryption_decryption(digest, derived_digest, plaintext, decrypted_ciphertext)
